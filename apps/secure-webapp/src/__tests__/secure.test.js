const request = require('supertest');
const app = require('../app-final');

describe('Secure app', () => {
  it('rejects SQL injection login', async () => {
    const res = await request(app)
      .post('/login')
      .send({ username: "' OR '1'='1", password: "' OR '1'='1" });
    expect(res.status).toBe(401);
  });

  it('accepts valid login and protects /admin', async () => {
    const agent = request.agent(app);
    const login = await agent.post('/login').send({ username: 'admin', password: 'admin123' });
    expect(login.status).toBe(200);
    const admin = await agent.get('/admin');
    expect(admin.status).toBe(200);
    expect(admin.body).toHaveProperty('user', 'admin');
  });
});
