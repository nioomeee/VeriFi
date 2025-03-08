import { Hono } from 'hono';
import { handle } from 'hono/vercel';
import { db } from '@/db';
import { documents, students, verifiers } from '@/db/schema';
import { and, eq } from 'drizzle-orm';
import { keyAuth } from '../../../../../middleware/keyAuth';

export const runtime = 'edge';

const app = new Hono().basePath('/api/verifier');

app.get('/get-all-verifiers', keyAuth, async (c) => {
  const allVerifiers = await db.select().from(verifiers);

  return c.json(allVerifiers);
});

app.get('/get-verifier-by-id', keyAuth, async (c) => {
  const verifierId = c.req.query('verifierId');

  if (!verifierId) {
    return c.json({ error: 'Missing verifier ID' }, 400);
  }

  const verifier = await db
    .select()
    .from(verifiers)
    .where(eq(verifiers.verifier_id, verifierId));

  if (verifier.length === 0) {
    return c.json({ error: 'Verifier not found' }, 404);
  }

  return c.json(verifier[0]);
});

app.patch('/update-verifier', keyAuth, async (c) => {
  const body = await c.req.json();
  const { id, name, wallet_address } = body;

  if (!id) {
    return c.json({ error: 'Missing verifier ID' }, 400);
  }

  const updateData: Record<string, string | null> = {};

  if (name !== undefined) updateData.name = name || null;
  if (wallet_address !== undefined)
    updateData.wallet_address = wallet_address || null;

  if (Object.keys(updateData).length === 0) {
    return c.json({ error: 'No valid fields to update' }, 400);
  }

  // Perform update operation
  await db.update(verifiers).set(updateData).where(eq(verifiers.user_id, id));

  return c.json({ message: 'Verifier updated successfully' });
});

app.get('/get-students-by-verifier-id', keyAuth, async (c) => {
  const verifierId = c.req.query('verifierId');

  if (!verifierId) {
    return c.json({ error: 'Missing verifier ID' }, 400);
  }

  const studentsList = await db
    .select()
    .from(students)
    .where(eq(students.verifier, verifierId));

  return c.json(studentsList);
});

app.post('/delete-verifier', keyAuth, async (c) => {
  const verifierId = c.req.query('verifierId');

  if (!verifierId) {
    return c.json({ error: 'Missing verifier ID' }, 400);
  }

  // Perform delete operation
  await db.delete(verifiers).where(eq(verifiers.verifier_id, verifierId));

  return c.json({ message: 'Verifier deleted successfully' });
});

app.post('/verify-document', keyAuth, async (c) => {
  const { documentId, verifierId } = await c.req.json();

  if (!documentId || !verifierId) {
    return c.json({ error: 'Missing document ID or verifier ID' }, 400);
  }

  await db
    .update(documents)
    .set({ status: 'verified', verifier_id: verifierId })
    .where(eq(documents.document_id, documentId));

  return c.json({ message: 'Document verified successfully' });
});

app.get('/get-all-verified-documents', keyAuth, async (c) => {
  const verifierId = String(c.req.query('verifierId'));
  if (!verifierId) {
    return c.json({ error: 'Missing verifier ID' }, 400);
  }

  const verifiedDocs = await db
    .select()
    .from(documents)
    .where(
      and(
        eq(documents.status, 'verified'),
        eq(documents.verifier_id, verifierId)
      )
    );

  return c.json(verifiedDocs);
});

export const GET = handle(app);
export const POST = handle(app);
export const PATCH = handle(app);
export const DELETE = handle(app);
