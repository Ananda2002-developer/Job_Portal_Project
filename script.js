
function showToast(msg){
      const t=document.createElement('div');
      t.textContent=msg;
      Object.assign(t.style,{
        position:'fixed',left:'50%',bottom:'24px',transform:'translateX(-50%)',
        background:'#4b2e58',color:'#fff',padding:'10px 14px',borderRadius:'8px',
        boxShadow:'0 8px 24px rgba(0,0,0,.2)',zIndex:9999,opacity:0,transition:'opacity .15s ease'
      });
      document.body.appendChild(t);
      requestAnimationFrame(()=>t.style.opacity=1);
      setTimeout(()=>{t.style.opacity=0; setTimeout(()=>t.remove(),160)},1200);
    }