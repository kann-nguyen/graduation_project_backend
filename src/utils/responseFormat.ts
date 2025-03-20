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
