'use client';
import { Card, CardTitle } from '@/components/ui/card';
import React from 'react';
import { getRequests } from '@/lib/get-student-data';

const RecentRequests = () => {
  const [requests, setRequests] = React.useState<
    { organization_name: string }[]
  >([]);
  const [loading, setLoading] = React.useState<boolean>(true);
  const [error, setError] = React.useState<string | null>(null);

  React.useEffect(() => {
    getRequests(1)
      .then((data) => {
        try {
          const parsedData = JSON.parse(data);
          if (Array.isArray(parsedData)) {
            setRequests(parsedData);
          } else {
            throw new Error('Invalid data format');
          }
        } catch {
          setError('Failed to parse response data.');
        }
      })
      .catch((err) => {
        setError(`Failed to load requests: ${err.message}`);
      })
      .finally(() => {
        setLoading(false);
      });
  }, []);

  return (
    <Card className="bg-[#EFEEFC] text-black rounded-xl p-6 pb-2">
      <CardTitle className="font-Rubik text-2xl font-semibold leading-9">
        Recent Requests
      </CardTitle>
      {loading && <p>Loading...</p>}
      {error && <p className="text-red-500">{error}</p>}

      {!loading && !error && requests.length > 0 ? (
        <ul className="mt-4 space-y-2">
          {requests.map((req, index) => (
            <li
              key={index}
              className="p-2 mb-4 bg-white text-black rounded-md shadow-md"
            >
              {req.organization_name}
            </li>
          ))}
        </ul>
      ) : (
        !loading && <p>No pending requests found.</p>
      )}
    </Card>
  );
};

export default RecentRequests;
