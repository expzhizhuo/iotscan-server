import{_ as T}from"./index-2c25bdbe.js";/* empty css                 */import{T as V}from"./TablesView-b69a0b48.js";import{H as E,aA as P,ax as R,A as B,a as S,_ as I,b as L,$ as N,m as O,p,V as o,P as s,u as m,l as X,T as _}from"./vue-657d2c67.js";import{b as h,a as l,w as $,m as A}from"./element-deea76d4.js";/* empty css                    *//* empty css               */const M=[{prop:"poc_name",label:"漏洞名称",showOverflowTooltip:!0},{prop:"vul_desc",label:"漏洞描述",showOverflowTooltip:!0},{prop:"vul_author",label:"作者"},{prop:"vul_leakLevel",label:"漏洞等级",sortable:!0},{prop:"vul_name",label:"影响产品",width:"100px"},{prop:"vul_range",label:"影响版本",width:"100px"},{prop:"has_exp",label:"有无EXP",slot:"has_exp",width:"80px"},{prop:"vul_vulDate",label:"公布日期"},{type:"date",prop:"vul_createDate",label:"编写日期"},{width:"180",label:"操作",buttons:[],slot:"action"}],j={class:"poc_search"},q=E({__name:"TasksReportView",setup(U){const d=P(),b=R(),c=B("reload"),n=S(),t={page:1,pageSize:10},v=I({tableDemoList:[],options:{showPagination:!0}});L(()=>d.query,async e=>{const{page:a,pageSize:u}=e;t.page=Number(a)||t.page,t.pageSize=Number(u)||t.pageSize,v.options.paginationConfig={total:100,currentPage:t.page,pageSize:t.pageSize,pageSizes:[10,20,30,40,50,100],layout:"total,prev, pager, next,sizes"}},{immediate:!0});const{options:g}=N(v),f=[{id:"183f77a7-a553-460d-bd27-c038dbf91975",poc_name:"大华 智慧园区综合管理平台 信息泄漏",vul_author:"zhizhuo",vul_name:"智慧园区综合管理平台",vul_range:"",vul_type:"Information Disclosure",vul_desc:"大华 智慧园区综合管理平台 /user_getUserInfoByUserName.action中存在API接口，导致管理园账号密码泄漏",vul_leakLevel:2,has_exp:!1,vul_device_name:"dahua-智慧园区综合管理平台",vul_vulDate:"2023-08-14",vul_createDate:"2023-10-16",vul_updateDate:"2023-10-16",create_time:"2023-10-26 16:12:21",create_user:{id:"e6333cd5-3b19-4c10-8e8f-b1893cea163d",create_username:"zhizhuo"}},{id:"951c3b96-02fc-4a2d-af9d-6b80b8bad0dd",poc_name:"泛微 E-Cology XXE (QVD-2023-16177)",vul_author:"zhizhuo",vul_name:"E-Cology",vul_range:"<10.58.2",vul_type:"XML Injection",vul_desc:"/rest/ofs/ReceiveCCRequestByXml接口存在XML Injection",vul_leakLevel:2,has_exp:!0,vul_device_name:"E-Cology",vul_vulDate:"2023-07-13",vul_createDate:"2023-10-16",vul_updateDate:"2023-10-16",create_time:"2023-10-26 16:12:21",create_user:{id:"e6333cd5-3b19-4c10-8e8f-b1893cea163d",create_username:"zhizhuo"}},{id:"bde8bb70-976c-4232-898e-03ae08bd6e2b",poc_name:"腾讯 企业微信（私有化版本）敏感信息泄露漏洞",vul_author:"zhizhuo",vul_name:"Tencent-企业微信",vul_range:"<2.7",vul_type:"Information Disclosure",vul_desc:"企业微信 /cgi-bin/gateway/agentinfo接口未授权情况下可直接获取企业微信secret等敏感信息",vul_leakLevel:3,has_exp:!0,vul_device_name:"Tencent-企业微信",vul_vulDate:"2023-08-12",vul_createDate:"2023-10-16",vul_updateDate:"2023-10-16",create_time:"2023-10-26 16:12:21",create_user:{id:"e6333cd5-3b19-4c10-8e8f-b1893cea163d",create_username:"zhizhuo"}}],y=(e,a,u)=>{switch(e){case"edit":alert("点击了编辑");break;case"delete":h.confirm("确认删除吗？","提示").then(()=>{l(JSON.stringify(a))}).catch(()=>null);break}},C=(e,a)=>{b.push({path:d.path,query:{page:e,pageSize:a}})},x=()=>{n.value,n.value?l.success(`搜索内容${n.value}`):(l.error("请输入搜索内容"),c())},k=()=>{c()},z=e=>{h.confirm("是否删除此POC？","提示",{confirmButtonText:"确定",cancelButtonText:"取消",type:"warning"}).then(()=>{l.success(`删除POC${e.id}成功`),c()}).catch(()=>{l({type:"info",message:"取消删除"}),c()})},w=e=>{l.success(`查看POC${e.id}内容`)};return(e,a)=>{const u=$,r=A;return X(),O("div",null,[p("div",null,[p("div",j,[o(u,{modelValue:n.value,"onUpdate:modelValue":a[0]||(a[0]=i=>n.value=i),placeholder:"请输入搜索内容",style:{width:"300px","margin-left":"10px"},clearable:""},null,8,["modelValue"]),o(r,{type:"primary",onClick:x,style:{"margin-left":"30px"}},{default:s(()=>[_("搜索")]),_:1}),o(r,{type:"primary",onClick:k},{default:s(()=>[_("重置")]),_:1})]),p("div",null,[o(V,{columns:m(M),"table-data":f,options:m(g),onPaginationChange:C,onCommand:y},{action:s(({row:i})=>[p("div",null,[o(r,{type:"primary",onClick:D=>w(i)},{default:s(()=>[_("查看")]),_:2},1032,["onClick"]),o(r,{type:"danger",onClick:D=>z(i)},{default:s(()=>[_("删除")]),_:2},1032,["onClick"])])]),_:1},8,["columns","options"])])])])}}});const Y=T(q,[["__scopeId","data-v-be4a4620"]]);export{Y as default};