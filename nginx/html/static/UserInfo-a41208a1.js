import{U as m,_ as x}from"./index-2c25bdbe.js";/* empty css               *//* empty css                *//* empty css                 *//* empty css                             *//* empty css                   *//* empty css               */import{a as c,r as U,H as w,I as V,J as A,K as B,w as K,m as C,v as D}from"./element-deea76d4.js";import{H as P,A as S,a as N,E as T,m as Y,p as o,V as e,P as a,l as z,T as t,U as l,ay as H,az as M}from"./vue-657d2c67.js";const d=i=>(H("data-v-8568ac94"),i=i(),M(),i),R={class:"userinfo-main"},j=d(()=>o("div",{class:"userinfo-title"},[o("span",null,"个人中心")],-1)),J={class:"userinfo-body"},q={class:"userinfo-username"},F={class:"dashboard-info"},G={class:"dashboard-api-key"},L=d(()=>o("span",{style:{"font-weight":"bold"}}," API KEY： ",-1)),O={style:{width:"60%","margin-left":"10px"}},Q={style:{"margin-left":"20px"}},W=d(()=>o("div",{class:"dashboard-api-key-desc"},[o("span",null,"*此API KEY可以获取当前用户创建的所有项目资产也可以查询指定项目资产")],-1)),X=P({__name:"UserInfo",setup(i){const r=S("reload"),s=N({}),f=()=>{m.rest_api_key().then(_=>{_.data.code==200?(c.success("重置成功"),r()):(c.success("重置失败"),r())})},v=()=>m.getUserInfo();return T(()=>{v().then(_=>{_.data.code==200?s.value=_.data.data:c.error("服务器异常")})}),(_,p)=>{const h=w,u=V,n=A,y=B,g=K,I=C,E=D,b=U;return z(),Y("div",R,[j,o("div",J,[e(b,{gutter:20},{default:a(()=>[e(E,{shadow:"hover"},{default:a(()=>[o("div",q,[o("span",null,[t("用户名："),e(h,{type:"success",size:"large"},{default:a(()=>[t(l(s.value.username),1)]),_:1})])]),e(u),o("div",F,[e(y,{border:"",column:1},{default:a(()=>[e(n,{label:"用户邮箱"},{default:a(()=>[t(l(s.value.email),1)]),_:1}),e(n,{label:"用户手机号"},{default:a(()=>[t(l(s.value.phone==null?"当前用户未绑定手机号":s.value.phone),1)]),_:1}),e(n,{label:"用户权限"},{default:a(()=>[t(l(s.value.permissions===1?"管理员":"普通用户"),1)]),_:1}),e(n,{label:"用户注册时间"},{default:a(()=>[t(l(s.value.create_time),1)]),_:1}),e(n,{label:"用户上次登陆时间"},{default:a(()=>[t(l(s.value.last_login),1)]),_:1}),e(n,{label:"用户上次登陆ip"},{default:a(()=>[t(l(s.value.last_login_ip==null?"来自火星的ip登陆":s.value.last_login_ip),1)]),_:1})]),_:1})]),e(u),o("div",G,[L,o("span",O,[e(g,{modelValue:s.value.api_key,"onUpdate:modelValue":p[0]||(p[0]=k=>s.value.api_key=k),readonly:"","suffix-icon":"el-icon-key",placeholder:"API KEY"},null,8,["modelValue"])]),o("span",Q,[e(I,{type:"primary",onClick:f},{default:a(()=>[t("重置")]),_:1})])]),W]),_:1})]),_:1})])])}}});const _e=x(X,[["__scopeId","data-v-8568ac94"]]);export{_e as default};