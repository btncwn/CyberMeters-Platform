import { DurableObject } from 'cloudflare:workers';
import { FREE_TOOL_TLS_LIMITS, PROBE_LIMITS, readBoundedJson, validateNetworkProbeRequest } from './contract.js';
import { validateFreeToolTlsReceipt, validateNetworkProbeReceipt } from './receipt.js';
import { collectorProgram } from './collector.js';
import { EXPOSURE_LIMITS, validateExposureRequest, validateExposureReceipt } from './exposure-contract.js';
import { exposureCollectorProgram } from './exposure-collector.js';
import { WEBSITE_CONTENT_LIMITS, validateWebsiteContentRequest, validateWebsiteContentReceipt } from './website-content-contract.js';
import { WEBSITE_CONTENT_PROGRAM } from './website-content-program.generated.js';
import { TLS_SLICE_LIMITS } from '../../../shared/tls/catalog.js';
import { projectTlsCollectorReceipt, validateTlsAssessmentReceipt, validateTlsAssessmentRequest } from './tls-contract.js';
import { TLS_COLLECTOR_PROGRAM } from './tls-collector-program.generated.js';

const ROUTES=['/collect','/exposure','/website-content','/tls-assessment','/free-tool-tls'];
// The anonymous free-tool profile runs only on its own route, so a scan's
// /collect request can never be one and a free check never takes a scan slot.
const validateRoute=(path,input)=>{
  if(path==='/tls-assessment')return validateTlsAssessmentRequest(input);
  if(path==='/website-content')return validateWebsiteContentRequest(input);
  if(path==='/exposure')return validateExposureRequest(input);
  const checked=validateNetworkProbeRequest(input);
  if(checked.ok&&(input.profile==='free_tool')!==(path==='/free-tool-tls'))return {ok:false,reason:'invalid_scope'};
  return checked;
};
const routeLimits=path=>path==='/tls-assessment'?TLS_SLICE_LIMITS:path==='/website-content'?WEBSITE_CONTENT_LIMITS:path==='/exposure'?EXPOSURE_LIMITS:path==='/free-tool-tls'?FREE_TOOL_TLS_LIMITS:PROBE_LIMITS;

export class NetworkProbeContainer extends DurableObject {
  constructor(ctx,env){super(ctx,env);this.busy=false;}
  async alarm(){if(this.ctx.container?.running)await this.ctx.container.destroy();}
  async fetch(request){
    const path=new URL(request.url).pathname;
    if(request.method!=='POST'||!ROUTES.includes(path))return new Response('Not found',{status:404});
    const exposure=path==='/exposure',websiteContent=path==='/website-content',tls=path==='/tls-assessment',freeTool=path==='/free-tool-tls';
    const limits=routeLimits(path);
    if(this.busy)return Response.json({error:'collector_busy'},{status:503});
    this.busy=true;
    let timer,abort;
    let processExited=false;
    try{
      const input=await readBoundedJson(request.body,limits.requestBytes);
      const validation=validateRoute(path,input);
      if(!validation.ok)return Response.json({error:validation.reason},{status:400});
      const remaining=Date.parse(input.deadline_at)-Date.now();
      const controller=new AbortController();
      abort=()=>{if(!processExited)controller.abort();this.ctx.container?.destroy().catch(()=>{});};
      timer=setTimeout(abort,remaining);
      if(request.signal.aborted)throw new Error('collector_aborted');
      request.signal.addEventListener('abort',abort,{once:true});
      // A recovered DO must never reuse a prior job's process or filesystem.
      if(this.ctx.container.running)await this.ctx.container.destroy();
      await this.ctx.storage.setAlarm(Date.parse(input.deadline_at));
      const image=tls?this.ctx.container.images?.tls:'cloudflare/debian-trixie';
      if(!image)throw new Error('tls_image_unavailable');
      this.ctx.container.start({image,instance:'lite',enableInternet:true,entrypoint:['sleep','infinity']});
      await this.ctx.container.setInactivityTimeout(120_000);
      // Large reviewed programs travel on stdin, avoiding OS argument-size caps.
      // The validated JSON is data embedded by JSON.stringify, never a program.
      const websiteProgram=websiteContent?WEBSITE_CONTENT_PROGRAM+`try{const result=await __runWebsiteContentCollector(${JSON.stringify(input)});process.stdout.write(JSON.stringify(result));}catch{process.exitCode=1;}`:null;
      const tlsProgram=tls?TLS_COLLECTOR_PROGRAM+`try{const result=await __runTlsCollector(${JSON.stringify(input)});process.stdout.write(JSON.stringify(result));}catch{process.exitCode=1;}`:null;
      const command=websiteContent||tls?['node','--input-type=module','-']:['node','--input-type=module','-e',(exposure?exposureCollectorProgram():collectorProgram())];
      const process=await this.ctx.container.exec(command,{stdin:new Response(tlsProgram||websiteProgram||JSON.stringify(input)).body,stdout:'pipe',stderr:'ignore',signal:controller.signal});
      const completion=process.exitCode.finally(()=>{processExited=true;clearTimeout(timer);request.signal.removeEventListener('abort',abort);});
      const [raw,exitCode]=await Promise.all([readBoundedJson(process.stdout,limits.responseBytes),completion]);
      if(exitCode!==0||controller.signal.aborted)throw new Error('collector_execution_failed');
      const receipt=tls?projectTlsCollectorReceipt(input,raw):raw;
      const checked=tls?validateTlsAssessmentReceipt(input,receipt):websiteContent?validateWebsiteContentReceipt(input,receipt):exposure?validateExposureReceipt(input,receipt):freeTool?validateFreeToolTlsReceipt(input,receipt):validateNetworkProbeReceipt(input,receipt);
      if(!checked.ok)throw new Error(checked.reason);
      return Response.json(receipt);
    }catch{return Response.json({error:'collector_unavailable'},{status:502});}
    finally{
      clearTimeout(timer);
      if(abort)request.signal.removeEventListener('abort',abort);
      try{if(this.ctx.container?.running)await this.ctx.container.destroy();}catch{}
      try{await this.ctx.storage.deleteAlarm();}catch{}
      this.busy=false;
    }
  }
}

// This Worker has no public route or workers.dev URL. Only the scan API's
// service binding can reach it. Two fixed scan slots and one free-tool slot
// bound account compute fan-out; callers cannot select arbitrary Durable Object
// names or container images.
export default {
  async fetch(request,env){
    const path=new URL(request.url).pathname;
    if(request.method!=='POST'||!ROUTES.includes(path))return new Response('Not found',{status:404});
    const limits=routeLimits(path);
    let input;
    try{input=await readBoundedJson(request.body,limits.requestBytes);}catch{return Response.json({error:'invalid_request'},{status:400});}
    const checked=validateRoute(path,input);if(!checked.ok)return Response.json({error:checked.reason},{status:400});
    // Free checks own one slot and never fall back: busy means busy, no retry.
    for(const slot of path==='/free-tool-tls'?['free-tool-slot-0']:['probe-slot-0','probe-slot-1']){
      const response=await env.PROBE_CONTAINERS.getByName(slot).fetch(`http://container${path}`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(input),signal:request.signal});
      if(response.status!==503)return response;
      await response.body?.cancel();
    }
    return Response.json({error:'collector_busy'},{status:503});
  },
};
