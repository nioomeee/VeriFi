import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

interface Document {
  document_id: number; // Changed from 'id'
  student_id: number;
  ipfs_hash: string;
  url: string;
  verifier_id: string;
  document_name: string; // Changed from 'name'
  createdAt: string; // Changed from 'uploaded_at'
  updatedAt: string;
  status: string;
  metadata: string; // Changed from 'type'
}

interface DocumentsTableProps {
  studentId: number;
  height: number;
  width: number;
}

const DocumentsTable = ({ studentId, height, width }: DocumentsTableProps) => {
  const [documents, setDocuments] = useState<Document[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchDocuments = async () => {
      try {
        const response = await fetch(
          `/api/student/get-all-documents?id=${studentId}`,
          {
            method: 'GET',
            headers: {
              'Content-Type': 'application/json',
              'x-api-key': 'DADDY-IS-HOME',
            },
          }
        );

        if (!response.ok) throw new Error(`Error: ${response.statusText}`);

        const data = await response.json();
        if (!Array.isArray(data)) throw new Error('Invalid response format');

        setDocuments(data);
      } catch (error) {
        console.error('Failed to fetch documents:', error);
        setError('Failed to load documents');
      } finally {
        setLoading(false);
      }
    };

    fetchDocuments();
  }, [studentId]);

  return (
    <div style={{ width: `${width}px` }}>
      <Card className="w-full bg-slate-800">
        <CardHeader>
          <CardTitle>Student Documents</CardTitle>
        </CardHeader>
        <CardContent>
          {loading ? (
            <p>Loading...</p>
          ) : error ? (
            <p className="text-red-500">{error}</p>
          ) : documents.length === 0 ? (
            <p className="text-gray-500">No documents found.</p>
          ) : (
            <div
              className="grid grid-cols-3 gap-4"
              style={{ maxHeight: `${height}px`, overflowY: 'auto' }}
            >
              {documents.map((doc) => (
                <Card key={doc.document_id} className="h-20">
                  {' '}
                  {/* Use document_id */}
                  <CardContent className="flex flex-col justify-between h-full p-4">
                    <div className="font-semibold truncate">
                      {doc.document_name}
                    </div>{' '}
                    {/* Use document_name */}
                    <div className="text-xs text-gray-500 text-right">
                      {doc.metadata} {/* Use metadata */}
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default DocumentsTable;
