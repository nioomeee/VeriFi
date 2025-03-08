import { useEffect, useState } from 'react';
import { PieChartComponent } from '@/components/ui/pie-chart';

type Document = {
  document_id: number;
  student_id: number;
  ipfs_hash: string;
  url: string;
  verifier_id: string;
  document_name: string;
  createdAt: string;
  updatedAt: string;
  status: string;
  metadata: string;
};

type PieChartData = {
  label: string;
  value: number;
  fill: string;
};

const fetchAllDocuments = async (studentId: number): Promise<Document[]> => {
  try {
    const response = await fetch(
      `api/student/get-all-documents?id=${studentId}`,
      {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': 'DADDY-IS-HOME',
        },
      }
    );
    if (!response.ok) {
      throw new Error('Failed to fetch documents');
    }
    return await response.json();
  } catch (error) {
    console.error('Error fetching documents:', error);
    return [];
  }
};

const organizeDocumentsByMetadata = (
  documents: Document[]
): Record<string, number> => {
  return documents.reduce((acc: Record<string, number>, doc) => {
    acc[doc.metadata] = (acc[doc.metadata] || 0) + 1;
    return acc;
  }, {});
};

const formatDataForPieChart = (
  metadataCounts: Record<string, number>
): PieChartData[] => {
  const colors = [
    'hsl(var(--chart-1))',
    'hsl(var(--chart-2))',
    'hsl(var(--chart-3))',
    'hsl(var(--chart-4))',
  ];
  return Object.entries(metadataCounts).map(([label, value], index) => ({
    label,
    value,
    fill: colors[index % colors.length],
  }));
};

const AllDocuments = ({ studentId }: { studentId: number }) => {
  const [chartData, setChartData] = useState<PieChartData[]>([]);

  useEffect(() => {
    const loadDocuments = async () => {
      const documents = await fetchAllDocuments(studentId);
      const metadataCounts = organizeDocumentsByMetadata(documents);
      const pieChartData = formatDataForPieChart(metadataCounts);
      setChartData(pieChartData);
    };

    loadDocuments();
  }, [studentId]);

  return (
    <div>
      <PieChartComponent
        height={412}
        width={325}
        title="Current Documents"
        data={chartData}
      />
    </div>
  );
};

export default AllDocuments;
