import{u as f}from"./index-71324df3.js";import{w as d,Z as c,a as i,b as w}from"./element-deea76d4.js";import{ag as t,H as _,aA as v,ax as C,_ as S,b as z,$ as k,m as E,V as N,P as V,u as m,p as r,l as D,U as P}from"./vue-657d2c67.js";import{T}from"./TablesView-b69a0b48.js";import"./index-2c25bdbe.js";/* empty css                    *//* empty css                 *//* empty css               */const{toClipboard:g}=f(),B=e=>t("div",{style:"margin-left: 50px;margin-right: 50px;"},[t("p",`名字：${e.name}`),t("p",`地址：${e.address}`),t("p",`日期：${e.date}`),t("div",{style:"display: flex;"},[t("div",{style:"flex: 1; position: relative; margin-right: 25px;"},[t(d,{type:"textarea",rows:16,modelValue:e.date,readonly:!0}),t(c,{style:"position: absolute; top: 10px; right:25px;float: right;  border: 1px padding: 1px;width:15px;height:15px",onClick:async()=>{await g(String(e.date)),i.success("复制成功")}})]),t("div",{style:"flex: 1; position: relative; margin-left: 25px;"},[t(d,{type:"textarea",rows:16,modelValue:e.address,readonly:!0}),t(c,{style:"position: absolute; top: 10px; right:25px;float: right;  border: 1px padding: 1px;width:15px;height:15px",onClick:async()=>{e.address,await g(e.address),i.success("复制成功")}})])])]),$=[{type:"expand",width:"50",render:({row:e})=>B(e)},{type:"index",width:"65",label:"No.",align:"center"},{prop:"avatar",label:"头像",width:"100",align:"center"},{prop:"address",label:"地址",slot:"address",showOverflowTooltip:!0,width:"180px"},{prop:"name",label:"姓名",width:"100"},{prop:"age",label:"年龄",width:"90",align:"center"},{prop:"gender",label:"性别",width:"90",slot:"gender",align:"center"},{prop:"mobile",label:"手机号",width:"180"},{prop:"email",label:"邮箱",showOverflowTooltip:!0},{width:"220",label:"操作",buttons:[{name:"编辑",type:"success",command:"edit",icon:"Edit"},{name:"删除",type:"danger",command:"delete",icon:"Delete"}]}],O=r("div",null,[r("h1",null,"基本表格")],-1),U=_({__name:"TestVIew",setup(e){const l=v(),u=C(),a={page:2,pageSize:50},p=S({tableDemoList:[],options:{showPagination:!0}});z(()=>l.query,async s=>{const{page:o,pageSize:n}=s;a.page=Number(o)||a.page,a.pageSize=Number(n)||a.pageSize,p.options.paginationConfig={total:100,currentPage:a.page,pageSize:a.pageSize,pageSizes:[10,20,30,40,50,100],layout:"total,prev, pager, next,sizes"}},{immediate:!0});const h=(s,o)=>{a.pageSize=o,a.page=s,u.push({path:l.path,query:{page:s,pageSize:o}})},{options:x}=k(p),b=[{date:1660737564e3,name:"佘太君",test:"123",address:"上海市普陀区金沙江路 1516 弄"},{date:14622912e5,name:"王小虎",test:"123",address:"上海市普陀区金沙江路 1517 弄"},{date:1462032e6,name:"王小帅",test:"123",address:"上海市普陀区金沙江路 1519 弄"},{date:14622048e5,name:"王小呆",test:"123",address:"上海市普陀区金沙江路 1516 弄"}],y=(s,o,n)=>{switch(s){case"edit":alert("点击了编辑");break;case"delete":w.confirm("确认删除吗？","提示").then(()=>{i(JSON.stringify(o))}).catch(()=>null);break}};return(s,o)=>(D(),E("div",null,[O,N(T,{columns:m($),"table-data":b,options:m(x),onPaginationChange:h,onCommand:y},{address:V(({row:n})=>[r("span",null,"演示slot使用--->"+P(n.address),1)]),_:1},8,["columns","options"])]))}});export{U as default};
