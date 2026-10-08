import http from 'node:http';
import {pathToFileURL} from 'node:url';
const emailPattern=/^[^\s@<>?,;:#]+@[^\s@<>?,;:#]+\.[^\s@<>?,;:#]+$/;
export function validateMail(data,domains){
  if(!data||typeof data!=='object')throw new Error('invalid_payload');
  const sender=String(data.sender||'').trim(),to=String(data.to||'').trim();
  if(sender.length>200||to.length>200||!emailPattern.test(sender)||!emailPattern.test(to))throw new Error('invalid_email');
  if(!domains.includes(sender.split('@')[1].toLowerCase()))throw new Error('sender_domain_not_allowed');
  if(typeof data.password!=='string'||!data.password||data.password.length>500)throw new Error('invalid_credentials');
  if(typeof data.subject!=='string'||!data.subject||data.subject.length>500||/[\r\n]/.test(data.subject))throw new Error('invalid_subject');
  if(typeof data.text!=='string'||data.text.length>100000)throw new Error('invalid_text');
  if(typeof data.pdfBase64!=='string'||data.pdfBase64.length>1800000||!/^[A-Za-z0-9+/]+={0,2}$/.test(data.pdfBase64))throw new Error('invalid_attachment');
  const pdf=Buffer.from(data.pdfBase64,'base64');if(pdf.subarray(0,5).toString()!=='%PDF-')throw new Error('invalid_pdf');
  return {sender,to,password:data.password,subject:data.subject,text:data.text,pdf,filename:String(data.filename||'proposal.pdf').replace(/[\\/:*?"<>|\x00-\x1F]/g,'_').slice(0,150)};
}
export function createSender({transportFactory,origin,smtpHost,smtpPort,domains,clock=Date.now}){
  if(!origin?.startsWith('https://')||!smtpHost||![465,587].includes(smtpPort)||!domains?.length)throw new Error('Missing or invalid production configuration');
  const attempts=new Map();
  const cleanup=setInterval(()=>{const now=clock();for(const [ip,entry]of attempts)if(now-entry.since>600000)attempts.delete(ip)},600000);cleanup.unref();
  const server=http.createServer(async(req,res)=>{
    res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-Type-Options','nosniff');
    const reply=(status,data)=>{res.writeHead(status,{'Content-Type':'application/json; charset=utf-8'});res.end(JSON.stringify(data))};
    if(req.headers.origin!==origin)return reply(403,{sent:false,error:'origin_not_allowed'});
    res.setHeader('Access-Control-Allow-Origin',origin);res.setHeader('Vary','Origin');
    if(req.method==='OPTIONS'){res.setHeader('Access-Control-Allow-Methods','POST, OPTIONS');res.setHeader('Access-Control-Allow-Headers','Content-Type');return reply(204,{})}
    if(req.method!=='POST'||req.url!=='/api/send-proposal')return reply(404,{sent:false});
    if(!String(req.headers['content-type']).startsWith('application/json'))return reply(415,{sent:false});
    // Ignore forwarded IP headers: the reverse proxy must also apply per-client limits.
    const ip=req.socket.remoteAddress;const now=clock();let entry=attempts.get(ip);if(!entry||now-entry.since>600000)entry={since:now,count:0};entry.count++;attempts.set(ip,entry);if(entry.count>20)return reply(429,{sent:false});
    let text='',chunks=[],size=0,transport;
    try{
      for await(const chunk of req){size+=chunk.length;if(size>2000000){reply(413,{sent:false});return}chunks.push(chunk)}
      text=Buffer.concat(chunks).toString('utf8');chunks=[];
      let mail;try{mail=validateMail(JSON.parse(text),domains)}catch(e){return reply(400,{sent:false,error:e.message})}
      transport=transportFactory({host:smtpHost,port:smtpPort,secure:smtpPort===465,requireTLS:smtpPort===587,tls:{minVersion:'TLSv1.2',rejectUnauthorized:true},connectionTimeout:10000,greetingTimeout:10000,socketTimeout:20000,auth:{user:mail.sender,pass:mail.password},logger:false,debug:false});
      const result=await transport.sendMail({from:mail.sender,to:mail.to,subject:mail.subject,text:mail.text,attachments:[{filename:mail.filename,content:mail.pdf,contentType:'application/pdf'}],disableFileAccess:true,disableUrlAccess:true});
      mail.password='';if(!result.accepted?.length)return reply(502,{sent:false});
      reply(200,{sent:true});
    }catch(e){reply(e.code==='EAUTH'?401:502,{sent:false,error:e.code==='EAUTH'?'authentication_failed':'smtp_send_failed'})}
    finally{transport?.close();text='';chunks=[]}
  });
  server.requestTimeout=20000;server.headersTimeout=10000;
  server.on('close',()=>clearInterval(cleanup));return server;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  const {default:nodemailer}=await import('nodemailer');
  const server=createSender({transportFactory:options=>nodemailer.createTransport(options),origin:process.env.ALLOWED_ORIGIN,smtpHost:process.env.SMTP_HOST,smtpPort:Number(process.env.SMTP_PORT),domains:(process.env.ALLOWED_SENDER_DOMAINS||'').toLowerCase().split(',').map(x=>x.trim()).filter(Boolean)});
  server.listen(Number(process.env.PORT)||3000,'127.0.0.1',()=>console.log('Kerio sender ready on loopback'));
}
