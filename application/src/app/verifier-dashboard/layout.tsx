import { redirect } from 'next/navigation';
import getRole from '@/lib/get-role';

export default async function Layout({
  children,
}: {
  children: React.ReactNode;
}) {
  const role = await getRole();

  if (role !== 'verifier') {
    redirect('/get-started');
  }

  return <>{children}</>;
}
