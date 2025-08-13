const createDeepLink = (type: 'phantom' | 'solflare', message: string) => {
  const baseUrl = window.location.href;
  const encodedMessage = encodeURIComponent(message);
  const encodedUrl = encodeURIComponent(baseUrl);

  const params = {
    message: encodedMessage,
    redirect: encodedUrl
  };

  const deepLink = type === 'phantom'
    ? `https://phantom.app/ul/v1/signMessage?${new URLSearchParams(params)}`
    : `https://solflare.com/ul/v1/signMessage?${new URLSearchParams(params)}`;

  return deepLink;
};

export const useDeepLink = () => {
  const openDeepLink = (type: 'phantom' | 'solflare', message: string) => {
    const deepLink = createDeepLink(type, message);
    window.location.href = deepLink;
  };

  return { openDeepLink };
};
