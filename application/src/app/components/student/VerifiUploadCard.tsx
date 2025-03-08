import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { UploadCloud } from 'lucide-react';
import { useState } from 'react';
import { toast } from 'sonner';

export default function VeriFiUploadCard() {
  const [file, setFile] = useState<File | null>(null);
  const [title, setTitle] = useState('');
  const [metadata, setMetadata] = useState('');
  const [uploading, setUploading] = useState(false);

  interface FileChangeEvent extends React.ChangeEvent<HTMLInputElement> {
    target: HTMLInputElement & { files: FileList };
  }

  const handleFileChange = (e: FileChangeEvent) => {
    const selectedFile = e.target.files[0];
    if (selectedFile && selectedFile.type === 'application/pdf') {
      setFile(selectedFile);
    } else {
      toast.error('Please upload a PDF file.');
    }
  };

  const handleUpload = async () => {
    if (!file || !title) {
      toast.error('Please select a file and provide a title');
      return;
    }

    try {
      setUploading(true);

      const formData = new FormData();
      formData.append('file', file);
      formData.append('title', title);
      formData.append('metadata', metadata);

      const response = await fetch('/api/upload', {
        method: 'POST',
        body: formData,
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Upload failed');
      }

      if (!data.fileUrl) {
        throw new Error('No file URL received from server');
      }

      console.log('File uploaded successfully!');
      console.log('IPFS File URL:', data.fileUrl);
      console.log('IPFS Metadata URL:', data.metadataUrl);
      console.log('File Hash:', data.fileHash);
      console.log('Metadata:', data.metadata);

      toast.success('File uploaded successfully!', {
        description: (
          <div>
            <p>
              File URL:{' '}
              <a
                href={data.fileUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="text-blue-500 hover:underline"
              >
                {data.fileUrl}
              </a>
            </p>
            <p>
              Metadata URL:{' '}
              <a
                href={data.metadataUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="text-blue-500 hover:underline"
              >
                {data.metadataUrl}
              </a>
            </p>
          </div>
        ),
        duration: 10000,
      });

      // Reset form
      setFile(null);
      setTitle('');
      setMetadata('');
    } catch (error) {
      console.error('Error uploading file:', error);
      toast.error('Error uploading file. Please try again.');
    } finally {
      setUploading(false);
    }
  };

  return (
    <Card className="w-[325px] h-[412px] bg-[#EFEEFC] text-black">
      <CardHeader>
        <CardTitle className="font-Rubik text-2xl font-semibold leading-9">
          Upload Document
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <Input
          placeholder="Title of the file"
          value={title}
          onChange={(e) => setTitle(e.target.value)}
        />
        <Input
          placeholder="Document metadata"
          value={metadata}
          onChange={(e) => setMetadata(e.target.value)}
        />
        <label className="flex items-center justify-center w-full border-2 border-dashed rounded-lg p-4 cursor-pointer hover:bg-gray-100">
          <UploadCloud className="mr-2" />
          <span>{file ? file.name : 'Click to upload'}</span>
          <input
            type="file"
            className="hidden"
            accept="application/pdf"
            onChange={handleFileChange}
          />
        </label>
        <Button className="w-full" onClick={handleUpload} disabled={uploading}>
          {uploading ? 'Uploading...' : 'Submit'}
        </Button>
      </CardContent>
    </Card>
  );
}
