import { DurableObject } from 'cloudflare:workers';
import { PROBE_LIMITS, readBoundedJson, validateNetworkProbeRequest } from './contract.js';
import { validateNetworkProbeReceipt } from './receipt.js';
import { collectorProgram } from './collector.js';

export class NetworkProbeContainer extends DurableObject {
  constructor(ctx,env){super(ctx,env);this.busy=false;}
  async alarm(){if(this.ctx.container?.running)await this.ctx.container.destroy();}
  async fetch(request){
    if(request.method!=='POST'||new URL(request.url).pathname!=='/collect')return new Response('Not found',{status:404});
    if(this.busy)return Response.json({error:'collector_busy'},{status:503});
    this.busy=true;
    let timer,abort;
    let processExited=false;
    try{
      const input=await readBoundedJson(request.body,PROBE_LIMITS.requestBytes);
      const validation=validateNetworkProbeRequest(input);
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
      const process=await this.ctx.container.exec(['node','--input-type=module','-e',collectorProgram()],{stdin:new Response(JSON.stringify(input)).body,stdout:'pipe',stderr:'ignore',signal:controller.signal});
      const completion=process.exitCode.finally(()=>{processExited=true;clearTimeout(timer);request.signal.removeEventListener('abort',abort);});
      const [receipt,exitCode]=await Promise.all([readBoundedJson(process.stdout,PROBE_LIMITS.responseBytes),completion]);
      if(exitCode!==0||controller.signal.aborted)throw new Error('collector_execution_failed');
      const checked=validateNetworkProbeReceipt(input,receipt);
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
    if(request.method!=='POST'||new URL(request.url).pathname!=='/collect')return new Response('Not found',{status:404});
    let input;
    try{input=await readBoundedJson(request.body,PROBE_LIMITS.requestBytes);}catch{return Response.json({error:'invalid_request'},{status:400});}
    const checked=validateNetworkProbeRequest(input);if(!checked.ok)return Response.json({error:checked.reason},{status:400});
    for(const slot of ['probe-slot-0','probe-slot-1']){
      const response=await env.PROBE_CONTAINERS.getByName(slot).fetch('http://container/collect',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(input),signal:request.signal});
      if(response.status!==503)return response;
      await response.body?.cancel();
    }
    return Response.json({error:'collector_busy'},{status:503});
  },
};
