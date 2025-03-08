export const getRequests = async (access_id: number) => {
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
    return JSON.stringify(data);
  } catch (error) {
    console.error('Failed to fetch pending requests:', error);
    return JSON.stringify({ error: (error as Error).message });
  }
};

export const getPendingRequests = async (access_id: number) => {
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

    // Ensure response is an array before mapping
    if (!Array.isArray(data)) {
      throw new Error('Invalid response format');
    }

    // Extract only organization names
    return data.length;
  } catch (error) {
    console.error('Failed to fetch pending requests:', error);
    return [];
  }
};
