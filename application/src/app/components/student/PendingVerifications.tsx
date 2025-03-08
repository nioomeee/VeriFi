import { useEffect, useState } from 'react';
import { Card, CardContent, CardTitle } from '@/components/ui/card';
import { FiSmile } from 'react-icons/fi';

const getPendingRequests = async (access_id: number) => {
  try {
    const response = await fetch('/api/access/get-requests', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': 'DADDY-IS-HOME',
      },
      body: JSON.stringify({ access_id }),
    });

    if (!response.ok) {
      throw new Error(`Error: ${response.statusText}`);
    }

    const data = await response.json();

    if (!Array.isArray(data)) {
      throw new Error('Invalid response format');
    }

    return data.length;
  } catch (error) {
    console.error('Failed to fetch pending requests:', error);
    return 0; // Return 0 instead of empty array for easier count handling
  }
};

const PendingVerifications = ({ accessId }: { accessId: number }) => {
  const [verifications, setVerifications] = useState<number | null>(null);

  useEffect(() => {
    const fetchVerifications = async () => {
      const count = await getPendingRequests(accessId);
      setVerifications(count);
    };

    fetchVerifications();
  }, [accessId]);

  return (
    <div>
      <Card className="bg-[#EFEEFC] text-black rounded-xl p-6 pb-2">
        <CardTitle className="font-Rubik text-2xl font-semibold leading-9">
          Pending Verifications
        </CardTitle>
        <CardContent>
          <div className="flex flex-row justify-center mb-0 mt-2 items-center gap-4 text-[#660012]">
            {verifications !== null && verifications > 0 ? (
              <div className="whitespace-nowrap justify-between p-4 bg-[#FF6681] rounded-lg w-full">
                {verifications === 1
                  ? '1 verification pending'
                  : `${verifications} verifications pending`}
              </div>
            ) : (
              <div className="flex flex-row justify-between p-4 bg-[#FFD6DD] rounded-lg w-52">
                No verifications <FiSmile size={30} />
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default PendingVerifications;
