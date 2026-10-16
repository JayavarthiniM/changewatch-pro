(() => {
  if (window.__changeWatchPickerActive) return;
  window.__changeWatchPickerActive = true;
  const outline = document.createElement('div');
  Object.assign(outline.style,{position:'fixed',zIndex:'2147483646',pointerEvents:'none',border:'2px solid #a99bff',background:'rgba(169,155,255,.12)',borderRadius:'3px',boxSizing:'border-box'});
  const banner=document.createElement('div');banner.textContent='ChangeWatch: click a region · Esc cancels';Object.assign(banner.style,{position:'fixed',top:'10px',left:'50%',transform:'translateX(-50%)',zIndex:'2147483647',background:'#171322',color:'#fff',font:'14px system-ui',padding:'10px 16px',borderRadius:'10px',boxShadow:'0 4px 24px #0008'});
  document.documentElement.append(outline,banner);
  const selectorFor=el=>{if(el.id)return '#'+CSS.escape(el.id);const parts=[];while(el&&el.nodeType===1&&el!==document.documentElement){let p=el.tagName.toLowerCase();if(el.classList.length)p+='.'+[...el.classList].filter(c=>/^[\w-]+$/.test(c)).slice(0,2).map(CSS.escape).join('.');const parent=el.parentElement;if(parent){const same=[...parent.children].filter(x=>x.tagName===el.tagName);if(same.length>1)p+=`:nth-of-type(${same.indexOf(el)+1})`;}parts.unshift(p);if(parts.length>=5)break;el=parent;}return parts.join(' > ')};
  const move=e=>{const r=e.target.getBoundingClientRect();Object.assign(outline.style,{left:r.left+'px',top:r.top+'px',width:r.width+'px',height:r.height+'px'});};
  const cleanup=()=>{document.removeEventListener('mousemove',move,true);document.removeEventListener('click',pick,true);document.removeEventListener('keydown',key,true);outline.remove();banner.remove();window.__changeWatchPickerActive=false;};
  const pick=e=>{if(e.target===banner||e.target===outline)return;e.preventDefault();e.stopPropagation();e.stopImmediatePropagation();const selector=selectorFor(e.target);chrome.storage.local.set({lastSelector:selector,lastSelectedText:(e.target.innerText||e.target.textContent||'').trim().slice(0,300),lastSelectedUrl:location.href});banner.textContent='Selected: '+selector;setTimeout(cleanup,800);};
  const key=e=>{if(e.key==='Escape')cleanup()};
  document.addEventListener('mousemove',move,true);document.addEventListener('click',pick,true);document.addEventListener('keydown',key,true);
})();
