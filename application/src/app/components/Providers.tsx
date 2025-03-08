'use client'; // Make this a client component

import { ThemeProvider } from 'next-themes';
import { ClerkProvider } from '@clerk/nextjs';
import { useState, useEffect } from 'react';

export function Providers({ children }: { children: React.ReactNode }) {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  // Return a minimal tree during SSR/initial render
  if (!mounted) {
    return (
      <div style={{ visibility: 'hidden' }}>
        <ClerkProvider>{children}</ClerkProvider>
      </div>
    );
  }

  return (
    <ClerkProvider>
      <ThemeProvider
        attribute="class"
        defaultTheme="dark"
        enableSystem={false}
        storageKey="verifi-theme"
        value={{
          light: 'light',
          dark: 'dark',
        }}
      >
        {children}
      </ThemeProvider>
    </ClerkProvider>
  );
}
