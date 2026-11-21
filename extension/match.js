export const hostOf = (url) => {
  try {
    return new URL(url).hostname.replace(/^www\./, '');
  } catch {
    return null;
  }
};

// Decides whether a login item may be offered to (and filled into) a page.
// shortcut: exact host match (www ignored), no subdomain matching; upgrade with a public-suffix list if needed
export function matchesPage(item, pageUrl) {
  if (item.type !== 'login' || !item.url) return false;
  let iu, pu;
  try {
    iu = new URL(item.url);
    pu = new URL(pageUrl);
  } catch {
    return false;
  }
  if (iu.protocol === 'https:' && pu.protocol !== 'https:') return false; // never fill an https login over http
  return hostOf(item.url) === hostOf(pageUrl);
}
