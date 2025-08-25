(function(){
  try{
    var raw = (location.pathname || '/').toLowerCase();
    // normalize: strip trailing slash (except root)
    var path = raw.endsWith('/') && raw !== '/' ? raw.slice(0, -1) : raw;
    // Allow public pages (with or without .html)
    var allow = new Set(['/','/index','/index.html','/login','/login.html','/register','/register.html']);
    var token = localStorage.getItem('token') || '';
    if(!token){
      if(!allow.has(path)){
        location.replace('/login');
      }
      return;
    }
    // Token exists: for protected pages, validate session quickly
    var protectedSet = new Set(['/chat','/chat.html','/account','/account.html']);
    if(protectedSet.has(path)){
      fetch('/api/me', { headers: { authorization: 'Bearer ' + token } })
        .then(function(r){ if(r.status===401 || r.status===403){ try{ localStorage.removeItem('token') }catch(e){}; location.replace('/login') } })
        .catch(function(){ try{ localStorage.removeItem('token') }catch(e){}; location.replace('/login') });
    }
  }catch(e){ /* no-op */ }
})();
