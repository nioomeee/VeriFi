'use client';
import { UserButton, useUser } from '@clerk/nextjs';
import React from 'react';
import { RiVerifiedBadgeFill } from 'react-icons/ri';

const UserTab = () => {
  const user = useUser();
  return (
    <div className="flex items-center gap-3 pr-4 rounded-lg">
      <div className="absolute left-[80rem] transform -translate-x-1/2">
        <UserButton
          appearance={{
            elements: {
              userButtonBox: 'flex flex-row items-center gap-2',
              userButtonAvatarBox: 'w-12 h-12 rounded-full bg-[#A379F7]',
            },
            layout: {
              logoPlacement: 'outside',
            },
          }}
        />
      </div>
      <span className="text-2xl flex flex-row justify-center items-center gap-2 leading-9 text-nowrap">
        {user.user?.fullName}
        {user.user?.publicMetadata.role === 'verifier' && (
          <RiVerifiedBadgeFill className="text-cyan-600" />
        )}
      </span>
    </div>
  );
};

export default UserTab;
