import { Hono } from 'hono';
import { handle } from 'hono/vercel';
import { keyAuth } from '@/../middleware/keyAuth';
import { access, organizations } from '@/db/schema';
import { eq } from 'drizzle-orm';
import { db } from '@/db';

export const runtime = 'edge';

const app = new Hono().basePath('/api/access');

app.get('/get-access', keyAuth, async (c) => {
  const id = Number(c.req.query('id'));

  if (!id) {
    return c.json({ error: 'Missing required fields' }, 400);
  }

  const data = await db.select().from(access).where(eq(access.access_id, id));

  return c.json(data);
});

app.get('/get-all-access-of-student', keyAuth, async (c) => {
  const student_id = Number(c.req.query('student_id'));

  if (!student_id) {
    return c.json({ error: 'Missing required fields' }, 400);
  }

  const data = await db
    .select()
    .from(access)
    .where(eq(access.student_id, student_id));

  return c.json(data);
});

app.post('/update-access', keyAuth, async (c) => {
  const body = await c.req.json();
  const { access_id, status } = body;

  if (!access_id) {
    return c.json({ error: 'Missing required fields' }, 400);
  }

  const updateData: Record<string, string | null> = {};

  if (status !== undefined) updateData.status = status || null;

  if (Object.keys(updateData).length === 0) {
    return c.json({ error: 'No valid fields to update' }, 400);
  }

  // Perform update operation
  await db
    .update(access)
    .set(updateData)
    .where(eq(access.access_id, access_id));

  return c.json({ message: 'Access updated successfully' });
});

app.post('/get-requests', keyAuth, async (c) => {
  const body = await c.req.json();
  const { access_id } = body;

  if (!access_id) {
    return c.json({ error: 'Missing required fields' }, 400);
  }

  const data = await db
    .select()
    .from(access)
    .where(eq(access.status, 'pending'));

  // Use Promise.all to wait for all database queries
  const result = await Promise.all(
    data.map(async (d) => {
      const organization = await db
        .select()
        .from(organizations)
        .where(eq(organizations.organization_id, d.organization_id));

      return {
        access_id: d.access_id,
        student_id: d.student_id,
        organization_id: d.organization_id,
        organization_name: organization[0]?.organization_name || 'Unknown',
        status: d.status,
      };
    })
  );

  return c.json(result);
});

export const GET = handle(app);
export const POST = handle(app);
