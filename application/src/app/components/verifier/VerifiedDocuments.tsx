import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

interface VerifiedDocument {
  document_id: string;
  student_id: string;
  ipfs_hash: string;
  url: string;
  verifier_id: string;
  document_name: string;
  createdAt: string;
  updatedAt: string;
  status: string;
  metadata: string;
}

const VerifiedDocuments = ({ verifierId }: { verifierId: string }) => {
  const [documents, setDocuments] = useState<VerifiedDocument[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchVerifiedDocuments = async () => {
      try {
        const response = await fetch(
          `/api/verifier/get-all-verified-documents?verifierId=${verifierId}`,
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

        setDocuments(data.slice(0, 6)); // Limiting to 5 documents
      } catch (error) {
        console.error('Failed to fetch verified documents:', error);
        setError('Failed to load documents');
      } finally {
        setLoading(false);
      }
    };

    fetchVerifiedDocuments();
  }, [verifierId]);

  return (
    <Card className="w-[422.400px] text-black bg-[#efeefc] p-4 pt-0 rounded-lg">
      <CardHeader>
        <CardTitle className="font-Rubik text-2xl font-semibold leading-9 ">
          Verified Documents
        </CardTitle>
      </CardHeader>
      <CardContent>
        {loading ? (
          <p>Loading...</p>
        ) : error ? (
          <p className="text-red-500">{error}</p>
        ) : documents.length === 0 ? (
          <p className="text-gray-500">No verified documents found.</p>
        ) : (
          <div className="grid grid-cols-2 gap-4">
            {documents.map((doc) => (
              <Card key={doc.document_id} className="p-4 border] rounded-lg">
                <CardContent className="flex flex-col justify-between">
                  <div className="font-semibold text-white truncate">
                    {doc.document_name}
                  </div>
                  <div className="text-xs text-gray-400">{doc.metadata}</div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
};

export default VerifiedDocuments;
