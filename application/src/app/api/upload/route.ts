import { Hono } from 'hono';
import { handle } from 'hono/vercel';
import pinataSDK from '@pinata/sdk';
import { Readable } from 'stream';

const app = new Hono();

const pinata = new pinataSDK(
  process.env.PINATA_API_KEY,
  process.env.PINATA_API_SECRET
);

interface UploadResponse {
  success: boolean;
  fileHash: string;
  metadataHash: string;
  metadata: {
    title: string;
    metadata: string;
    fileName: string;
    fileSize: number;
    fileType: string;
    ipfsHash: string;
    timestamp: string;
  };
  fileUrl: string;
  metadataUrl: string;
}

// Helper function to convert any Sets to Arrays in an object
function sanitizeResponse<T>(obj: T): T {
  if (obj === null || typeof obj !== 'object') {
    return obj;
  }

  if (obj instanceof Set) {
    return Array.from(obj) as unknown as T;
  }

  if (Array.isArray(obj)) {
    return obj.map(sanitizeResponse) as unknown as T;
  }

  if (obj && typeof obj === 'object') {
    const sanitized = Object.fromEntries(
      Object.entries(obj).map(([key, value]) => [key, sanitizeResponse(value)])
    );
    return sanitized as T;
  }

  return obj;
}

app.post('/api/upload', async (c) => {
  try {
    const formData = await c.req.formData();
    const file = formData.get('file') as File;
    const title = formData.get('title') as string;
    const metadata = formData.get('metadata') as string;

    if (!file || !title) {
      return c.json({ error: 'File and title are required' }, 400);
    }

    // Convert file to buffer and create a readable stream
    const buffer = Buffer.from(await file.arrayBuffer());
    const stream = Readable.from(buffer);

    // Add file name to the stream object
    Object.defineProperty(stream, 'path', {
      value: file.name,
      writable: true,
      enumerable: true,
      configurable: true,
    });

    // Upload file to Pinata
    const fileResult = await pinata.pinFileToIPFS(stream, {
      pinataMetadata: {
        name: file.name,
      },
      pinataOptions: {
        cidVersion: 0,
      },
    });

    // Create metadata object
    const metadataObj = {
      title,
      metadata,
      fileName: file.name,
      fileSize: file.size,
      fileType: file.type,
      ipfsHash: fileResult.IpfsHash,
      timestamp: new Date().toISOString(),
    };

    // Upload metadata to Pinata
    const metadataResult = await pinata.pinJSONToIPFS(metadataObj, {
      pinataMetadata: {
        name: `${file.name}-metadata`,
      },
    });

    // Construct gateway URLs
    const fileUrl = `https://gateway.pinata.cloud/ipfs/${fileResult.IpfsHash}`;
    const metadataUrl = `https://gateway.pinata.cloud/ipfs/${metadataResult.IpfsHash}`;

    const response: UploadResponse = {
      success: true,
      fileHash: fileResult.IpfsHash,
      metadataHash: metadataResult.IpfsHash,
      metadata: metadataObj,
      fileUrl,
      metadataUrl,
    };

    // Sanitize the response to convert any Sets to Arrays
    return c.json(sanitizeResponse(response));
  } catch (error) {
    console.error('Upload error:', error);
    return c.json(
      {
        error: 'Failed to upload file',
        details: error instanceof Error ? error.message : 'Unknown error',
      },
      500
    );
  }
});

export const GET = handle(app);
export const POST = handle(app);
