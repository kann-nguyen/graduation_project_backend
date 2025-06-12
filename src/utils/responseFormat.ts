export const errorResponse = (message: string) => ({
  status: "error",
  data: null,
  message,
});

export const successResponse = (data: any, message: string) => ({
  status: "success",
  data,
  message,
});

/**
 * Handle Axios timeout errors and other common scanning errors
 * @param error - The error object from axios or other sources
 * @param context - Context information (e.g., "Scanner X", "artifact Y")
 * @returns Object with handled error info
 */
export const handleScanningError = (error: any, context: string) => {
  const errorInfo = {
    isTimeout: false,
    isConnectionError: false,
    message: '',
    shouldCrash: false
  };

  if (error instanceof Error) {
    // Handle timeout specifically
    if (error.message.includes('timeout') || (error as any).code === 'ECONNABORTED') {
      errorInfo.isTimeout = true;
      errorInfo.message = `${context} timed out. This is expected for large scans.`;
      errorInfo.shouldCrash = false; // Don't crash the app on timeout
    } 
    // Handle connection errors
    else if ((error as any).code === 'ECONNREFUSED' || (error as any).code === 'ENOTFOUND') {
      errorInfo.isConnectionError = true;
      errorInfo.message = `${context} connection failed: ${error.message}`;
      errorInfo.shouldCrash = false; // Don't crash on connection errors
    }
    // Handle other errors
    else {
      errorInfo.message = `${context} failed: ${error.message}`;
      errorInfo.shouldCrash = false; // Generally don't crash on scanning errors
    }
  } else {
    errorInfo.message = `${context} failed with unknown error: ${error}`;
    errorInfo.shouldCrash = false;
  }

  return errorInfo;
};
