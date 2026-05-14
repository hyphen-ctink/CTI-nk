import axios from 'axios';

const api = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080',
  withCredentials: true,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    const status = error.response?.status;
    const PUBLIC_PATHS = ['/login', '/signup'];

    if (status === 401) {
      if (typeof window !== 'undefined' && !PUBLIC_PATHS.includes(window.location.pathname)) {
        sessionStorage.clear();
        window.location.href = '/login';
      }
    }
    // USER 계정이 ADMIN 전용 API를 직접 호출하는 경우 /overview로 리다이렉트
    // 로그인 페이지에서의 403(inactive/pending 계정)은 로그인 페이지에서 개별 처리하므로 제외
    if (status === 403) {
      if (typeof window !== 'undefined' && !PUBLIC_PATHS.includes(window.location.pathname)) {
        window.location.href = '/overview';
      }
    }

    return Promise.reject(error);
  }
);

export default api;