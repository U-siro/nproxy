webpackJsonp([1],{"248o":function(t,e){},GiRC:function(t,e){},NHnr:function(t,e,o){"use strict";Object.defineProperty(e,"__esModule",{value:!0});var s=o("7+uW"),r={render:function(){var t=this.$createElement,e=this._self._c||t;return e("div",{attrs:{id:"app"}},[this._m(0),this._v(" "),e("div",{staticClass:"container"},[e("router-view")],1),this._v(" "),e("br")])},staticRenderFns:[function(){var t=this.$createElement,e=this._self._c||t;return e("nav",{staticClass:"navbar navbar-expand-lg navbar-light bg-light sticky-top"},[e("div",{staticClass:"container"},[e("a",{staticClass:"navbar-brand",attrs:{href:"/"}},[e("strong",[this._v("nRoute Web UI")])]),this._v(" "),e("button",{staticClass:"navbar-toggler navbar-toggler-right",attrs:{type:"button","data-toggle":"collapse","data-target":"#navbarNavDropdown","aria-controls":"navbarNavDropdown","aria-expanded":"false","aria-label":"Toggle navigation"}},[e("span",{staticClass:"navbar-toggler-icon"})]),this._v(" "),e("div",{staticClass:"navbar-collapse text-center collapse justify-content-end",attrs:{id:"navbarNavDropdown"}},[e("ul",{staticClass:"nav navbar-nav"})])])])}]};var a=o("VU/8")({name:"App"},r,!1,function(t){o("GiRC")},null,null).exports,n=o("/ocq"),i=o("fZjL"),c=o.n(i),u=o("mtWM"),l=o.n(u),d={name:"HelloWorld",data:function(){return{items:[]}},beforeMount:function(){var t=this;console.log(this.items),l.a.get("/routes").then(function(e){c()(e.data.data).forEach(function(o){var s=e.data.data[o];s.host=s.host.join(", "),s.id=o,t.items.push(s)})})}},f={render:function(){var t=this,e=t.$createElement,o=t._self._c||e;return o("div",{staticClass:"hello"},[o("h1",[t._v("nRoute Dashboard")]),t._v(" "),o("div",{staticClass:"list-group"},[t._l(t.items,function(e){return o("router-link",{key:e.id,staticClass:"list-group-item list-group-item-action",attrs:{to:"/routesEditor/"+e.id}},[t._v(t._s(e.host))])}),t._v(" "),o("router-link",{staticClass:"list-group-item list-group-item-action",attrs:{to:"/routesEditor/new"}},[t._v("Create new route")])],2)])},staticRenderFns:[]};var v=o("VU/8")(d,f,!1,function(t){o("VjQa")},"data-v-64ff1146",null).exports;function p(){for(var t="",e="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",o=0;o<5;o++)t+=e.charAt(Math.floor(Math.random()*e.length));return t}var h={name:"HelloWorld",data:function(){return{routeInfo:{},https:!1}},beforeMount:function(){var t=this;"new"==this.$route.params.routeId?this.routeInfo={host:[],target:[],secure:!1,websocket:!1,lockDetails:!1}:l.a.get("/routes/"+this.$route.params.routeId).then(function(e){console.log(e),t.routeInfo=e.data,0!=e.data.https&&(t.https=!0),t.routeInfo.secure={cert:"",key:""}}),this.routeInfo.secure={cert:"",key:""}},methods:{removeRoute:function(){var t=this;$.notify({message:"Removing route.."},{type:"success"}),l.a.delete("/routes/"+this.$route.params.routeId).then(function(e){$.notify({message:"Route has been successfully removed."},{type:"success"}),t.$router.push("/")})},removeHost:function(){this.routeInfo.host.pop()},addHost:function(){this.routeInfo.host.push(p()+".invalid")},removeTarget:function(){this.routeInfo.target.pop()},addTarget:function(){this.routeInfo.target.push("http://"+p()+".invalid")},save:function(){$.notify({message:"Updating Route.."},{type:"info"});var t={host:this.routeInfo.host,target:this.routeInfo.target,secure:!!this.https&&this.routeInfo.secure,websocket:this.routeInfo.websocket,lockDetails:this.routeInfo.lockDetails},e=void 0;e="new"==this.$route.params.routeId?l.a.post("/routes",t):l.a.patch("/routes/"+this.$route.params.routeId,t);var o="new"==this.$route.params.routeId,s=this.$router;e.then(function(t){o?($.notify({message:"Route has been successfully created."},{type:"success"}),s.push(t.headers.location.replace("/routes/","/routesEditor/"))):$.notify({message:"Route has been successfully updated."},{type:"success"})}).catch(function(t){console.log(t),"Conflict"==t.response.data?$.notify({message:"<strong>Host is conflicting with another route.</strong>"},{type:"danger"}):$.notify({message:"<strong>There was a problem to save route.</strong>"},{type:"danger"})})},letsEncrypt:function(t){var e=this;$.notify({message:"Generating certificate..."},{type:"info"}),l.a.get("/certificate/letsencrypt/"+this.routeInfo.host.join(",")).then(function(t){console.log(t.data),$.notify({message:"Certificate has been successfully updated using Let's Encrypt!"},{type:"success"}),e.routeInfo.secure={cert:t.data.certs.cert,key:t.data.certs.privkey}}).catch(function(t){console.log(t),$.notify({message:"<strong>There was a problem to generate certificate using Let's Encrypt!.</strong><br>Error Code: "+t.response.data.error.code},{type:"danger"})})}},mounted:function(){}},m={render:function(){var t=this,e=t.$createElement,o=t._self._c||e;return o("div",{staticClass:"hello"},[o("h3",[t._v("nRoute Route Editor: "+t._s(t.routeInfo.host.join(", ")))]),t._v(" "),o("label",[t._v("Hosts")]),t._v(" "),t._l(t.routeInfo.host,function(e,s){return o("div",{key:"host_"+s,staticClass:"input-group mb-3"},[o("input",{directives:[{name:"model",rawName:"v-model",value:t.routeInfo.host[s],expression:"routeInfo.host[index]"}],staticClass:"form-control",attrs:{type:"text",placeholder:"Host"},domProps:{value:t.routeInfo.host[s]},on:{input:function(e){e.target.composing||t.$set(t.routeInfo.host,s,e.target.value)}}}),t._v(" "),t.routeInfo.host.length-1==s?o("div",{staticClass:"input-group-prepend"},[o("button",{staticClass:"remove-field btn btn-danger",attrs:{type:"button"},on:{click:t.removeHost}},[t._v("Remove")])]):t._e()])}),t._v(" "),o("button",{staticClass:"add-field btn btn-success",attrs:{type:"button"},on:{click:t.addHost}},[t._v("Add host")]),t._v(" "),o("br"),t._v(" "),o("label",[t._v("Target")]),t._v(" "),t._l(t.routeInfo.target,function(e,s){return o("div",{key:"target_"+s,staticClass:"input-group mb-3"},[o("input",{directives:[{name:"model",rawName:"v-model",value:t.routeInfo.target[s],expression:"routeInfo.target[index]"}],staticClass:"form-control",attrs:{type:"text",placeholder:"Target"},domProps:{value:t.routeInfo.target[s]},on:{input:function(e){e.target.composing||t.$set(t.routeInfo.target,s,e.target.value)}}}),t._v(" "),t.routeInfo.target.length-1==s?o("div",{staticClass:"input-group-prepend"},[o("button",{staticClass:"remove-field btn btn-danger",attrs:{type:"button"},on:{click:t.removeTarget}},[t._v("Remove")])]):t._e()])}),t._v(" "),o("button",{staticClass:"add-field btn btn-success",attrs:{type:"button"},on:{click:t.addTarget}},[t._v("Add target")]),t._v(" "),o("br"),t._v(" "),o("br"),t._v(" "),o("div",{staticClass:"form-check"},[o("input",{directives:[{name:"model",rawName:"v-model",value:t.routeInfo.websocket,expression:"routeInfo.websocket"}],staticClass:"form-check-input",attrs:{type:"checkbox",value:"",id:"defaultCheck1"},domProps:{checked:Array.isArray(t.routeInfo.websocket)?t._i(t.routeInfo.websocket,"")>-1:t.routeInfo.websocket},on:{change:function(e){var o=t.routeInfo.websocket,s=e.target,r=!!s.checked;if(Array.isArray(o)){var a=t._i(o,"");s.checked?a<0&&t.$set(t.routeInfo,"websocket",o.concat([""])):a>-1&&t.$set(t.routeInfo,"websocket",o.slice(0,a).concat(o.slice(a+1)))}else t.$set(t.routeInfo,"websocket",r)}}}),t._v(" "),o("label",{staticClass:"form-check-label",attrs:{for:"defaultCheck1"}},[t._v("\n      Proxy WebSocket\n    ")])]),t._v(" "),o("div",{staticClass:"form-check"},[o("input",{directives:[{name:"model",rawName:"v-model",value:t.routeInfo.lockDetails,expression:"routeInfo.lockDetails"}],staticClass:"form-check-input",attrs:{type:"checkbox",value:"",id:"defaultCheck2"},domProps:{checked:Array.isArray(t.routeInfo.lockDetails)?t._i(t.routeInfo.lockDetails,"")>-1:t.routeInfo.lockDetails},on:{change:function(e){var o=t.routeInfo.lockDetails,s=e.target,r=!!s.checked;if(Array.isArray(o)){var a=t._i(o,"");s.checked?a<0&&t.$set(t.routeInfo,"lockDetails",o.concat([""])):a>-1&&t.$set(t.routeInfo,"lockDetails",o.slice(0,a).concat(o.slice(a+1)))}else t.$set(t.routeInfo,"lockDetails",r)}}}),t._v(" "),o("label",{staticClass:"form-check-label",attrs:{for:"defaultCheck2"}},[t._v("\n      Hide route info from /cdn-cgi/trace\n    ")])]),t._v(" "),o("div",{staticClass:"form-check"},[o("input",{directives:[{name:"model",rawName:"v-model",value:t.https,expression:"https"}],staticClass:"form-check-input",attrs:{type:"checkbox",value:"",id:"defaultCheck3"},domProps:{checked:Array.isArray(t.https)?t._i(t.https,"")>-1:t.https},on:{change:function(e){var o=t.https,s=e.target,r=!!s.checked;if(Array.isArray(o)){var a=t._i(o,"");s.checked?a<0&&(t.https=o.concat([""])):a>-1&&(t.https=o.slice(0,a).concat(o.slice(a+1)))}else t.https=r}}}),t._v(" "),o("label",{staticClass:"form-check-label",attrs:{for:"defaultCheck3"}},[t._v("\n      Use HTTPS\n    ")])]),t._v(" "),t.https?o("div",{staticClass:"httpsSettings"},[o("label",{attrs:{for:"httpsCertificate"}},[t._v("HTTPS Certificate")]),t._v(" "),o("textarea",{directives:[{name:"model",rawName:"v-model",value:t.routeInfo.secure.cert,expression:"routeInfo.secure.cert"}],staticClass:"form-control",attrs:{id:"httpsCertificate"},domProps:{value:t.routeInfo.secure.cert},on:{input:function(e){e.target.composing||t.$set(t.routeInfo.secure,"cert",e.target.value)}}}),t._v(" "),o("label",{attrs:{for:"httpsKey"}},[t._v("HTTPS Private Key")]),t._v(" "),o("textarea",{directives:[{name:"model",rawName:"v-model",value:t.routeInfo.secure.key,expression:"routeInfo.secure.key"}],staticClass:"form-control",attrs:{id:"httpsKey"},domProps:{value:t.routeInfo.secure.key},on:{input:function(e){e.target.composing||t.$set(t.routeInfo.secure,"key",e.target.value)}}}),t._v(" "),o("br"),t._v(" "),o("button",{staticClass:"btn btn-success",on:{click:t.letsEncrypt}},[t._v("Generate Let's Encrypt Certificate")])]):t._e(),t._v(" "),o("br"),t._v(" "),o("button",{staticClass:"btn btn-success",on:{click:t.save}},[t._v("Save route")]),t._v(" "),o("router-link",{staticClass:"btn btn-warning",attrs:{to:"/",tag:"button"}},[t._v("Go back")]),t._v(" "),"new"!==this.$route.params.routeId?o("button",{staticClass:"btn btn-danger",on:{click:t.removeRoute}},[t._v("Remove route")]):t._e()],2)},staticRenderFns:[]};var g=o("VU/8")(h,m,!1,function(t){o("248o")},"data-v-4e129b0c",null).exports;s.a.use(n.a);var b=new n.a({routes:[{path:"/",name:"Dashboard",component:v},{path:"/routesEditor/:routeId",name:"Route Edit Mode",component:g}],mode:"history"});s.a.config.productionTip=!1,new s.a({el:"#app",router:b,components:{App:a},template:"<App/>"})},VjQa:function(t,e){}},["NHnr"]);
//# sourceMappingURL=app.3c65b5c0c43c72448706.js.map