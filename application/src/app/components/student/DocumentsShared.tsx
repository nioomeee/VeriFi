import React from 'react';
import ChartTable from '@/../public/svgs/chart-table.svg';
import User1 from '@/../public/svgs/user1.svg';
import User2 from '@/../public/svgs/user2.svg';
import User3 from '@/../public/svgs/user3.svg';
import { Card, CardTitle } from '@/components/ui/card';

const DocumentsShared = ({
  data,
}: {
  data: { top: number; second: number; third: number };
}) => {
  return (
    <Card
      className="relative flex flex-col bg-[#EFEEFC] text-blue-500 rounded-xl overflow-hidden"
      style={{
        width: '520px',
        height: '412px',
        backgroundImage: `url(${ChartTable.src})`,
        backgroundSize: '90% 90%',
        backgroundPosition: 'center 120px',
        backgroundRepeat: 'no-repeat',
      }}
    >
      <CardTitle className="absolute font-Rubik text-2xl font-semibold leading-9 text-black left-6 top-4">
        Documents Shared
      </CardTitle>
      <div className="flex flex-row gap-2 p-12 justify-center items-center">
        <div className="flex flex-col w-1/3 justify-center items-center pt-4">
          <div
            className="w-12"
            style={{
              width: '64px',
              height: '64px',
              backgroundImage: `url(${User1.src})`,
              backgroundSize: '90% 90%',
              backgroundPosition: 'center',
              backgroundRepeat: 'no-repeat',
            }}
          ></div>
          <span className="text-white bg-[#9087E5] px-4 py-1 mt-8 rounded-lg">
            {data.second}
          </span>
        </div>
        <div className="flex flex-col w-1/3 justify-center items-center pb-16">
          <div
            className="w-12"
            style={{
              width: '64px',
              height: '64px',
              backgroundImage: `url(${User2.src})`,
              backgroundSize: '90% 90%',
              backgroundPosition: 'center',
              backgroundRepeat: 'no-repeat',
            }}
          ></div>
          <span className="text-white bg-[#9087E5] px-4 py-1 mt-8 rounded-lg">
            {data.top}
          </span>
        </div>
        <div className="flex flex-col w-1/3 justify-center items-center pt-16">
          <div
            className="w-12"
            style={{
              width: '64px',
              height: '64px',
              backgroundImage: `url(${User3.src})`,
              backgroundSize: '90% 90%',
              backgroundPosition: 'center',
              backgroundRepeat: 'no-repeat',
            }}
          ></div>
          <span className="text-white bg-[#9087E5] px-4 py-1 mt-8 rounded-lg">
            {data.third}
          </span>
        </div>
      </div>
    </Card>
  );
};

export default DocumentsShared;
