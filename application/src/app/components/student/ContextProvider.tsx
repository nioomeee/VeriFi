import React from 'react';
import AllDocuments from './AllDocuments';
import PendingVerifications from './PendingVerifications';
import RecentRequests from './RecentRequests';
import DocumentsShared from './DocumentsShared';
import DocumentsTable from './DocumentsTable';
import Developers from '../Developers';
import Avatar from '@/../public/svgs/avatar.svg';
// import { currentUser } from '@clerk/nextjs/server';

const ContextProvider = () => {
  //   const user = await currentUser();

  //   const userId = Number(user?.publicMetadata.id);

  return (
    <div className="flex-1 overflow-x-hidden p-10 text-white">
      <div className="flex flex-row gap-10">
        <AllDocuments studentId={1} />

        <div className="flex flex-col gap-10">
          <RecentRequests />
          <PendingVerifications accessId={1} />
        </div>
        <div>
          <DocumentsShared data={{ top: 5, second: 4, third: 1 }} />
        </div>
      </div>
      <div className="relative flex flex-row gap-10 mt-6">
        <DocumentsTable height={500} width={750} studentId={1} />
        <div
          className="absolute w-56 h-56 bottom-3 right-64 rounded-full"
          style={{
            backgroundImage: `url(${Avatar.src})`,
            backgroundSize: 'cover',
          }}
        ></div>
        <Developers height={254} width={450} />
        <div
          className="absolute w-56 h-56 bottom-3 right-64 rounded-full"
          style={{
            backgroundImage: `url(${Avatar.src})`,
            backgroundSize: 'cover',
          }}
        ></div>
        <div className="absolute w-64 h-36 bottom-10 -right-16 rounded-lg bg-[#EFEEFC] items-center justify-center flex flex-col p-4 text-center">
          <h2 className="font-Rubik text-black text-4xl font-bold tracking-wide">
            How you doing??
          </h2>
        </div>
      </div>
    </div>
  );
};

export default ContextProvider;
