const request = require('supertest');
const app = require('../app');

describe('Vulnerable app', () => {
  it('allows SQL injection login', async () => {
    const payload = { username: "admin' --", password: 'anything' };
    const res = await request(app).post('/login').send(payload);
    // Depending on SQLite parsing, fallback generic tautology:
    const res2 = await request(app).post('/login').send({ username: "' OR '1'='1", password: "' OR '1'='1" });
    expect([res.status, res2.status]).toContain(200);
  });

  it('reflects XSS input', async () => {
    const q = `<img src=x onerror=alert(1)>`;
    const res = await request(app).get('/search').query({ q });
    expect(res.text).toContain(q); // reflected unsanitized
  });
});
