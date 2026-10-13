import { DurableObject } from 'cloudflare:workers';
import { PROBE_LIMITS, readBoundedJson, validateNetworkProbeRequest } from './contract.js';
import { validateNetworkProbeReceipt } from './receipt.js';
import { collectorProgram } from './collector.js';
import { EXPOSURE_LIMITS, validateExposureRequest, validateExposureReceipt } from './exposure-contract.js';
import { exposureCollectorProgram } from './exposure-collector.js';
import { WEBSITE_CONTENT_LIMITS, validateWebsiteContentRequest, validateWebsiteContentReceipt } from './website-content-contract.js';
import { WEBSITE_CONTENT_PROGRAM } from './website-content-program.generated.js';

export class NetworkProbeContainer extends DurableObject {
  constructor(ctx,env){super(ctx,env);this.busy=false;}
  async alarm(){if(this.ctx.container?.running)await this.ctx.container.destroy();}
  async fetch(request){
    const path=new URL(request.url).pathname;
    if(request.method!=='POST'||!['/collect','/exposure','/website-content'].includes(path))return new Response('Not found',{status:404});
    const exposure=path==='/exposure',websiteContent=path==='/website-content';
    const limits=websiteContent?WEBSITE_CONTENT_LIMITS:exposure?EXPOSURE_LIMITS:PROBE_LIMITS;
    if(this.busy)return Response.json({error:'collector_busy'},{status:503});
    this.busy=true;
    let timer,abort;
    let processExited=false;
    try{
      const input=await readBoundedJson(request.body,limits.requestBytes);
      const validation=websiteContent?validateWebsiteContentRequest(input):exposure?validateExposureRequest(input):validateNetworkProbeRequest(input);
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
      this.ctx.container.start({image:'cloudflare/debian-trixie',instance:'lite',enableInternet:true,entrypoint:['sleep','infinity']});
      await this.ctx.container.setInactivityTimeout(120_000);
      // Large reviewed programs travel on stdin, avoiding OS argument-size caps.
      // The validated JSON is data embedded by JSON.stringify, never a program.
      const websiteProgram=websiteContent?WEBSITE_CONTENT_PROGRAM+`try{const result=await __runWebsiteContentCollector(${JSON.stringify(input)});process.stdout.write(JSON.stringify(result));}catch{process.exitCode=1;}`:null;
      const command=websiteContent?['node','--input-type=module','-']:['node','--input-type=module','-e',(exposure?exposureCollectorProgram():collectorProgram())];
      const process=await this.ctx.container.exec(command,{stdin:new Response(websiteProgram||JSON.stringify(input)).body,stdout:'pipe',stderr:'ignore',signal:controller.signal});
      const completion=process.exitCode.finally(()=>{processExited=true;clearTimeout(timer);request.signal.removeEventListener('abort',abort);});
      const [receipt,exitCode]=await Promise.all([readBoundedJson(process.stdout,limits.responseBytes),completion]);
      if(exitCode!==0||controller.signal.aborted)throw new Error('collector_execution_failed');
      const checked=websiteContent?validateWebsiteContentReceipt(input,receipt):exposure?validateExposureReceipt(input,receipt):validateNetworkProbeReceipt(input,receipt);
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
// service binding can reach it. Two fixed slots bound account compute fan-out;
// callers cannot select arbitrary Durable Object names or container images.
export default {
  async fetch(request,env){
    const path=new URL(request.url).pathname;
    if(request.method!=='POST'||!['/collect','/exposure','/website-content'].includes(path))return new Response('Not found',{status:404});
    const exposure=path==='/exposure',websiteContent=path==='/website-content';
    const limits=websiteContent?WEBSITE_CONTENT_LIMITS:exposure?EXPOSURE_LIMITS:PROBE_LIMITS;
    let input;
    try{input=await readBoundedJson(request.body,limits.requestBytes);}catch{return Response.json({error:'invalid_request'},{status:400});}
    const checked=websiteContent?validateWebsiteContentRequest(input):exposure?validateExposureRequest(input):validateNetworkProbeRequest(input);if(!checked.ok)return Response.json({error:checked.reason},{status:400});
    for(const slot of ['probe-slot-0','probe-slot-1']){
      const response=await env.PROBE_CONTAINERS.getByName(slot).fetch(`http://container${path}`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(input),signal:request.signal});
      if(response.status!==503)return response;
      await response.body?.cancel();
    }
    return Response.json({error:'collector_busy'},{status:503});
  },
};
