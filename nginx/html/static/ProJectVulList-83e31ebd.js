import{_ as $,L as M}from"./index-2c25bdbe.js";/* empty css                   *//* empty css               *//* empty css                 */import{T as H}from"./TablesView-b69a0b48.js";import{H as B,l as b,m as I,p as o,V as a,P as e,T as p,U as i,F as G,a8 as K,O as D,S as N,u as L,ay as j,az as X,aA as Q,ax as Y,a as q,A as Z,E as ee,_ as ae,$ as te,b as oe}from"./vue-657d2c67.js";import{P as le}from"./index-46f5d838.js";import{u as se}from"./taskinfo-15095992.js";/* empty css                   *//* empty css               *//* empty css               */import{u as ne}from"./index-71324df3.js";import{q as ce,r as ie,I as re,L as R,a as k,w as O,e as pe,W as ue,X as _e,m as de,F as fe,b as ge,H as me}from"./element-deea76d4.js";/* empty css                    */const ve=[{prop:"poc_info",label:"漏洞名称",slot:"poc_info",showOverflowTooltip:!0,width:"200"},{prop:"vul_desc",label:"漏洞描述",slot:"vul_desc",showOverflowTooltip:!0},{prop:"vul_leakLevel",label:"漏洞等级",slot:"vul_leakLevel",sortable:!0,width:"110"},{prop:"vul_name",label:"影响产品",slot:"vul_name",width:"100",showOverflowTooltip:!0},{prop:"vul_range",label:"影响版本",slot:"vul_range",width:"100",sortable:!0},{prop:"has_exp",label:"有无EXP",slot:"has_exp",width:"80"},{prop:"vul_vulDate",label:"公布日期",slot:"vul_vulDate",width:"120"},{width:"180",label:"操作",buttons:[],slot:"action"}];const S=u=>(j("data-v-f0befe6d"),u=u(),X(),u),he={class:"container"},ye={class:"dialog-title"},we=S(()=>o("strong",{class:"info-label"},"目标地址：",-1)),be=S(()=>o("strong",{class:"info-label"},"漏洞名称：",-1)),ke=S(()=>o("strong",{class:"info-label"},"漏洞描述：",-1)),Ce=S(()=>o("strong",{class:"info-label"},"漏洞等级：",-1)),xe=S(()=>o("strong",{class:"info-label"},"发现时间：",-1)),Se={class:"dialog-request"},Ve={key:0,class:"step-indicator"},ze=B({__name:"ProjectVulInfoWinodws",props:{data:{}},setup(u){const n=u,{toClipboard:m}=ne();n.data&&n.data;const V=s=>({0:"提示",1:"低危",2:"中危",3:"高危",4:"严重"})[s],v=async s=>{if(!s){k.warning("请输入文本再复制");return}try{await m(s),k.success("复制成功！")}catch(_){k.error(`复制失败: ${_}`),console.error(_)}};return(s,_)=>{const l=ce,f=ie,c=re,C=O,x=pe,z=ue,P=_e;return b(),I("div",he,[o("div",ye,[a(f,{class:"info-row",type:"flex",align:"middle"},{default:e(()=>[a(l,{span:6},{default:e(()=>[we]),_:1}),a(l,{span:18,class:"info-content"},{default:e(()=>[p(i(s.data.result.VerifyInfo.URL),1)]),_:1})]),_:1}),a(f,{class:"info-row",type:"flex",align:"middle"},{default:e(()=>[a(l,{span:6},{default:e(()=>[be]),_:1}),a(l,{span:18,class:"info-content"},{default:e(()=>[p(i(s.data.poc_info.poc_name),1)]),_:1})]),_:1}),a(f,{class:"info-row",type:"flex",align:"middle"},{default:e(()=>[a(l,{span:6},{default:e(()=>[ke]),_:1}),a(l,{span:18,class:"info-content"},{default:e(()=>[p(i(s.data.poc_info.vul_desc),1)]),_:1})]),_:1}),a(f,{class:"info-row",type:"flex",align:"middle"},{default:e(()=>[a(l,{span:6},{default:e(()=>[Ce]),_:1}),a(l,{span:18,class:"info-content"},{default:e(()=>[p(i(V(s.data.poc_info.vul_leakLevel)),1)]),_:1})]),_:1}),a(f,{class:"info-row",type:"flex",align:"middle"},{default:e(()=>[a(l,{span:6},{default:e(()=>[xe]),_:1}),a(l,{span:18,class:"info-content"},{default:e(()=>[p(i(s.data.create_time),1)]),_:1})]),_:1})]),a(c,{"content-position":"left"},{default:e(()=>[p("漏洞证明")]),_:1}),o("div",Se,[(b(!0),I(G,null,K(s.data.result.request,(w,E)=>(b(),D(P,{key:E},{default:e(()=>[s.data.result.request.length>1?(b(),I("div",Ve,[o("span",null,"第"+i(E+1)+"步",1)])):N("",!0),a(z,{title:"请求数据包"},{default:e(()=>[a(C,{type:"textarea",autosize:{minRows:12,maxRows:12},"model-value":w.request,readonly:"",class:"data-package"},null,8,["model-value"]),a(x,{onClick:T=>v(w.request),class:"copy_icon_absolute"},{default:e(()=>[a(L(R))]),_:2},1032,["onClick"])]),_:2},1024),a(z,{title:"响应数据包"},{default:e(()=>[a(C,{type:"textarea",autosize:{minRows:12,maxRows:12},"model-value":w.response,readonly:"",class:"data-package"},null,8,["model-value"]),a(x,{onClick:T=>v(w.response),class:"copy_icon_absolute"},{default:e(()=>[a(L(R))]),_:2},1032,["onClick"])]),_:2},1024)]),_:2},1024))),128))])])}}});const Ee=$(ze,[["__scopeId","data-v-f0befe6d"]]),qe=u=>(j("data-v-1dda0d53"),u=u(),X(),u),Ie={class:"poc_search"},Le=qe(()=>o("span",{class:"dialog-header"},"漏洞详情",-1)),Pe=B({__name:"ProJectVulList",setup(u){const n=Q(),m=Y(),V=se(),v=q(!1),s=q(),_=Z("reload"),l=q(),f=n.query.task_ids||V.getTaskIds()||"";ee(()=>{f||(M.hideLoading(),m.replace("/404")),V.setTaskIds(String(f))}),n.query.search&&(l.value=n.query.search);const c={page:Number(n.query.page)||1,pageSize:Number(n.query.pageSize)||10,search:String(n.query.search)||""},C=ae({options:{showPagination:!0}}),x=q([]),{options:z}=te(C),P=async(r,d,h=c.search)=>{await m.push({path:n.path,query:{page:r,pageSize:d,search:h}}),_()},w=async()=>{l.value,l.value?(await m.push({path:n.path,query:{page:1,pageSize:10,search:l.value}}),_()):(k.error("请输入搜索内容"),await m.push({path:n.path,query:{page:1,pageSize:10,search:""}}),_())},E=async()=>{await m.push({path:n.path,query:{page:1,pageSize:10,search:""}}),_()},T=r=>{ge.confirm("是否使用EXP进行漏洞利用？","提示",{confirmButtonText:"确定",cancelButtonText:"取消",type:"warning"}).then(()=>{k.success(`EXP${r.id}利用成功`),_()}).catch(()=>{k({type:"info",message:"取消EXP利用"}),_()})},U=r=>{s.value=r,v.value=!0},W=(r=1,d=10,h="",g=1,y="")=>le.get_tasks_result({page:r,page_size:d,task_id:h,task_type:g,search:y});oe(()=>n.query,async r=>{const{page:d,pageSize:h,search:g}=r;c.page=Number(d)||c.page,c.pageSize=Number(h)||c.pageSize,c.search=g||"",W(c.page,c.pageSize,f,1,c.search).then(y=>{x.value=y.data.data.list,C.options.paginationConfig={total:y.data.data.total,currentPage:c.page,pageSize:c.pageSize,pageSizes:[10,20,30,40,50,100],layout:"total,prev, pager, next,sizes"}})},{immediate:!0});const A=r=>({0:"提示",1:"低危",2:"中危",3:"高危",4:"严重"})[r];return(r,d)=>{const h=O,g=de,y=me,F=fe;return b(),I("div",null,[o("div",null,[o("div",Ie,[a(h,{size:"large",modelValue:l.value,"onUpdate:modelValue":d[0]||(d[0]=t=>l.value=t),placeholder:"请输入搜索内容",style:{width:"300px","margin-left":"10px"},clearable:""},null,8,["modelValue"]),a(g,{type:"primary",size:"large",round:"",onClick:w,style:{"margin-left":"30px"}},{default:e(()=>[p("搜索 ")]),_:1}),a(g,{type:"primary",size:"large",round:"",onClick:E},{default:e(()=>[p("重置")]),_:1})]),o("div",null,[a(H,{columns:L(ve),"table-data":x.value,options:L(z),onPaginationChange:P},{poc_info:e(({row:t})=>[o("span",null,i(t.poc_info.poc_name),1)]),vul_desc:e(({row:t})=>[o("span",null,i(t.poc_info.vul_desc),1)]),vul_leakLevel:e(({row:t})=>[o("span",null,[a(y,{type:{0:"",1:"success",2:"warning",3:"danger",4:"danger"}[t.poc_info.vul_leakLevel]},{default:e(()=>[p(i(A(t.poc_info.vul_leakLevel)),1)]),_:2},1032,["type"])])]),vul_name:e(({row:t})=>[o("span",null,i(t.poc_info.vul_name),1)]),vul_range:e(({row:t})=>[o("span",null,i(t.poc_info.vul_range),1)]),has_exp:e(({row:t})=>[o("span",null,[a(y,{type:{false:"info",true:"success"}[t.poc_info.has_exp]},{default:e(()=>[p(i(t.poc_info.has_exp?"有":"无"),1)]),_:2},1032,["type"])])]),vul_vulDate:e(({row:t})=>[o("span",null,i(t.poc_info.vul_vulDate),1)]),action:e(({row:t})=>[o("div",null,[a(g,{type:"primary",onClick:J=>U(t)},{default:e(()=>[p("查看")]),_:2},1032,["onClick"]),t.poc_info.has_exp?(b(),D(g,{key:0,type:"danger",onClick:J=>T(t)},{default:e(()=>[p("利用 ")]),_:2},1032,["onClick"])):N("",!0)])]),_:1},8,["columns","table-data","options"])])]),o("div",null,[a(F,{modelValue:v.value,"onUpdate:modelValue":d[1]||(d[1]=t=>v.value=t),draggable:"",overflow:"",width:"60%"},{header:e(()=>[Le]),default:e(()=>[a(Ee,{dialog:v.value,data:s.value},null,8,["dialog","data"])]),_:1},8,["modelValue"])])])}}});const Me=$(Pe,[["__scopeId","data-v-1dda0d53"]]);export{Me as default};