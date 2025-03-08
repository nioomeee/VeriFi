import { Card, CardContent, CardTitle } from '@/components/ui/card';
import { FiMeh } from 'react-icons/fi';
import React, { useEffect, useState } from 'react';

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

const getRecentlyVerified = async (
  verifier_id: string
): Promise<VerifiedDocument | null> => {
  try {
    const response = await fetch(
      `/api/verifier/get-all-verified-documents?verifierId=${verifier_id}`,
      {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': 'DADDY-IS-HOME',
        },
      }
    );

    if (!response.ok) {
      throw new Error(`Error: ${response.statusText}`);
    }

    const data = await response.json();

    if (!Array.isArray(data)) {
      throw new Error('Invalid response format');
    }

    return data[0];
  } catch (error) {
    console.error('Failed to fetch pending requests:', error);
    return null;
  }
};

const RecentlyVerified = ({ verifierId }: { verifierId: string }) => {
  const [verified, setVerified] = useState<VerifiedDocument | null>(null);

  useEffect(() => {
    const fetchVerified = async () => {
      const lastVerified = await getRecentlyVerified(verifierId);
      setVerified(lastVerified);
    };

    fetchVerified();
  }, [verifierId]);

  return (
    <div>
      <Card className="bg-[#EFEEFC] text-black rounded-xl p-6 pb-2">
        <CardTitle className="font-Rubik text-2xl font-semibold leading-9 ">
          Recent Verified
        </CardTitle>
        <CardContent>
          <div className="flex flex-row justify-center mb-0 mt-2 items-center gap-4 text-[#660012] w-full">
            {verified ? (
              <div>
                <div className="flex flex-row p-2 bg-[#FFD6DD] rounded-lg justify-center items-center w-full text-center">
                  <div className="border-r-2 border-solid border-white pr-2">
                    <div className="font-bold">Document</div>
                    <div>{verified.document_name}</div>
                  </div>
                  <div className="border-r-2 border-solid border-white pr-2 pl-2">
                    <div className="font-bold">Student</div>
                    <div>{verified.student_id}</div>
                  </div>
                  <div>
                    <div className="font-bold pl-2">Status</div>
                    <div>{verified.status}</div>
                  </div>
                </div>
              </div>
            ) : (
              <div className="flex flex-row justify-between p-4 bg-[#FFD6DD] rounded-lg w-52">
                No requests found <FiMeh size={30} />
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default RecentlyVerified;
