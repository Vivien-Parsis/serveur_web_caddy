const fastify = require('fastify')({logger: true})
const path = require('node:path');
const crypto = require('crypto');
const fs = require('node:fs');

fastify.register(require('@fastify/mongodb'), {
  forceClose: true,
  url: 'mongodb://127.0.0.1:27017/caddy'
})
fastify.register(require('@fastify/jwt'),{
    secret : 'supersecret'
});
fastify.register(require('@fastify/static'),{ 
    root: path.join(__dirname),
    prefix: '/',
    decorateReply: true
})
fastify.register(require('@fastify/formbody'));

fastify.decorate("authenticate", async (request, reply) => {
    try {
        await request.jwtVerify()
    } catch (err) {
        reply.send(err)
    }
})
fastify.register(require('@fastify/secure-session'), {
    // the name of the attribute decorated on the request-object, defaults to 'session'
    sessionName: 'session',
    // the name of the session cookie, defaults to value of sessionName
    cookieName: 'token',
    // adapt this to point to the directory where secret-key is located
    key: fs.readFileSync(path.join(__dirname, 'secret-key')),
    cookie: {
        path: '/'
        // options for setCookie, see https://github.com/fastify/fastify-cookie
    }
  })
fastify.get('/', (request, reply) => {
    reply.header('Content-Type', 'text/HTML')
    reply.sendFile("index.html");
})

fastify.get('/messages', async (req, reply)=>{
    const caddy = fastify.mongo.db.collection('message');
    try{
        const result = await caddy.find().toArray();
        return result;
    }catch(err){
        return err;
    }
})

fastify.post('/messages',  async (req, reply) => {
    const caddy = fastify.mongo.db.collection('message');
    try{
        const result = await caddy.insertOne(req.body);
        reply.code(201);
        reply.send("message created");
    }catch(err){
        return err;
    }
})

fastify.post('/signin', async (req,reply)=>{
    reply.header("Access-Control-Allow-Origin", "*");
    const json = JSON.parse(req.body);
    const mail = json.mail;
    const password = json.password;
    if(mail.trim()==="" || password.trim()===""){
        reply.send("err");
    }
    const caddy = fastify.mongo.db.collection('utilisateurs');
    try{
        let hash = crypto.createHash("sha256").update(password).digest("base64");
        const users = await caddy.findOne({mail:mail,password:hash});
        if(users!=null){
            const token = fastify.jwt.sign({mail:users.mail});
            req.session.set('token',{mail:users.mail});
            return {token};
        }
        return reply.send("unknown")
    }catch(err){
        return err;
    }
})
fastify.post('/signup', async (req,reply)=>{
    const mail = req.body.mail;
    const password = req.body.password;
    if(mail.trim()===""||password.trim()===""||mail==undefined||password==undefined){
        reply.send("err");
    }
    const caddy = fastify.mongo.db.collection('utilisateurs');
    try{
        let hash = crypto.createHash("sha256").update(password).digest("base64");
        let users = await caddy.findOne({mail:mail,password:hash});
        if(users!=null){
            reply.send("already exist");
        }
        users = await caddy.insertOne({mail:mail,password:hash});
        return users;
    }catch(err){
        return err;
    }
})
fastify.get("/secret",{onRequest: [fastify.authenticate]},
    async function(request, reply) {
      return request.user
})
fastify.get("/private",(req,reply)=>{
    const data = req.session.get('token')
    if (!data) {
    reply.code(404).send()
    return
    }
    reply.send(data)
})
fastify.listen({ port: 3000 }, (err, address) => {
    console.log(`listening to ${address}`)
    if (err) throw err;
})