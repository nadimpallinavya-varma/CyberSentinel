const fs = require('fs');
const source = fs.readFileSync('index.html', 'utf8');
if (!source.includes("api('/demo/'+endpoint,{method:'POST'})")) {
  throw new Error('Detection Center must submit demo scenarios with POST');
}
if (!source.includes("result=await api('/demo/'")) {
  throw new Error('Detection Center must use the backend demo endpoint');
}
if (source.includes("api('/api/demo/'") || source.includes("api('/api/stats')") || source.includes("api('/api/incidents')")) {
  throw new Error('Frontend API paths must not duplicate the /api base path');
}
if (!source.includes('await refreshData()')) {
  throw new Error('Detection Center must refresh backend incidents after a successful demo');
}
if (!source.includes('Cannot reach the CyberSentinel API')) {
  throw new Error('Detection Center must expose a specific connectivity error');
}
console.log('frontend regression contract: ok');
