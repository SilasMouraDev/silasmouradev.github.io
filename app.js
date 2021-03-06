var ProcyonTest = function(){

    var uuid_index='00000000-0000-0000-0000-000000000000';
    var index_pass=null;
    var index={
        section:['Home'],
        file:{},
        actual_section:'Home',
        actual_file:'0'
    };

    function uuidv4(){
        return ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g,c =>(c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16));
    }
    function getdate(){
        let d = new Date();
        let f = [
                     d.getFullYear(),
                    (d.getMonth()+1).toString().padStart(2,'0'),
                    (d.getDate()).toString().padStart(2,'0')
                ].join('-')
                +' '+
                [
                    (d.getHours()).toString().padStart(2,'0'),
                    (d.getMinutes()).toString().padStart(2,'0'),
                    (d.getSeconds()).toString().padStart(2,'0')
                ].join(':');
        return f;
    }
    function humanFileSize(bytes, si=false, dp=1) {
        const thresh = si ? 1000 : 1024;
      
        if (Math.abs(bytes) < thresh) {
          return bytes + ' B';
        }
      
        const units = si 
          ? ['kB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'] 
          : ['KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB', 'ZiB', 'YiB'];
        let u = -1;
        const r = 10**dp;
      
        do {
          bytes /= thresh;
          ++u;
        } while (Math.round(Math.abs(bytes) * r) / r >= thresh && u < units.length - 1);
      
      
        return bytes.toFixed(dp) + ' ' + units[u];
    }

    function arrayBufferToBase64(buf){
        var binary = '';
        var bytes = new Uint8Array( buf );
        var len = bytes.byteLength;
        for (var i = 0; i < len; i++) {
            binary += String.fromCharCode( bytes[ i ] );
        }
        return window.btoa( binary );
    }
    function base64ToArrayBuffer(b64){
        var binary_string =  window.atob(b64);
        var len = binary_string.length;
        var bytes = new Uint8Array( len );
        for (var i = 0; i < len; i++)        {
            bytes[i] = binary_string.charCodeAt(i);
        }
        return bytes.buffer;
    }
    function stringToArrayBuffer(str){
        return new TextEncoder().encode(str);
    }
    function arrayBufferToString(buf){
        return new TextDecoder().decode(buf);
    }
 
    function procedure_encrypt(pass,data,cb){
        // https://github.com/diafygi/webcrypto-examples/#aes-gcm
        let pass_pad = stringToArrayBuffer(pass.padEnd(32,'0').substring(0,32));
        let iv_arr = window.crypto.getRandomValues(new Uint8Array(12));
        let data_buf = stringToArrayBuffer(JSON.stringify(data));
        window.crypto.subtle.importKey("raw", pass_pad, {name:"AES-GCM",}, false, ["encrypt", "decrypt"])
        .then(function(key){
            window.crypto.subtle.encrypt({name:"AES-GCM",iv:iv_arr,tagLength:128},key,data_buf)
            .then(function(encrypted){
                cb(true,[iv_arr,encrypted]);
            })
            .catch(function(err){ cb(false,err); });
        })
        .catch(function(err){ cb(false,err); });
    }
    function procedure_decrypt(pass,data,cb){
        let iv_arr = data[0];
        let data_buf = data[1];
        let pass_pad = stringToArrayBuffer(pass.padEnd(32,'0').substring(0,32));

        window.crypto.subtle.importKey("raw", pass_pad, {name:"AES-GCM",}, false, ["encrypt", "decrypt"])
        .then(function(key){
            window.crypto.subtle.decrypt({name: "AES-GCM", iv:iv_arr,tagLength: 128},key,data_buf)
            .then(function(decrypted){
                let dec_obj=JSON.parse(arrayBufferToString(decrypted));
                cb(true,dec_obj);
            })
            .catch(function(err){ cb(false,err); });
        })
        .catch(function(err){ cb(false,err); });
    }
    function procedure_genpass(cb){
        window.crypto.subtle.generateKey({name:"AES-GCM",length:256,},true,["encrypt", "decrypt"])
        .then(function(key){
            window.crypto.subtle.exportKey("jwk",key)
            .then(function(keydata){cb(true,keydata.k);})
            .catch(function(err){cb(false,err);});
        })
        .catch(function(err){cb(false,err);});       
    }

    function procedure_save(pass,uuid,data,cb){
        procedure_encrypt(pass,data,(res,ret)=>{
            if(res==false){ cb(res,ret); return false; }
            localforage.setItem(uuid,ret).then(function(value){
                if(uuid!=uuid_index){
                    index.file[uuid].date=getdate();
                    index.file[uuid].size=ret[0].length+ret[1].byteLength;
                    procedure_save(index_pass,uuid_index,index,(ret,res)=>{
                        cb(ret,res);
                    });
                }
                else cb(true,null);
            }).catch(function(err){ cb(false,err); });
        });
    }
    function procedure_load(pass,uuid,cb){
        localforage.getItem(uuid).then(function(encrypted){
            procedure_decrypt(pass,encrypted,(res,ret)=>{
                cb(res,ret);
            });
        }).catch(function(err){
            cb(false,err);
        });
    }
    function procedure_newf(section,name,cb){
        procedure_genpass((res,ret)=>{
            if(res==false){ cb(res,ret); return false; }

            let f={ uuid:uuidv4(), sect:section, name:name, date:getdate(), size:0, pass:ret };
            index.file[f['uuid']]=f;

            procedure_save(index_pass,uuid_index,index,(res,ret)=>{
                if(res==false){ cb(res,ret); return false; }

                procedure_save(f['pass'],f['uuid'],'',(res,ret)=>{
                    cb(res,ret);
                });
            });
        });
    }

    // INTERFACE
/*    
    let html_editor_layout = new w2layout({
        name:'html_editor_layout',
        panels: [
            {type:'top',title:'file_name.html',size:70},
            {type:'main',overflow:'hidden'}
        ]
    });
    let html_editor_toolbar = new w2toolbar({
        name:'html_editor_toolbar',
        items: [
            { type: 'button', id: 'HET_SAV', text: 'Save', icon: 'fa fa-floppy-disk' },
            { type: 'spacer' },
            { type: 'button', id: 'HET_LOK', text: 'Lock Screen', icon: 'fa fa-lock' },
            { type: 'spacer' },
            { type: 'button', id: 'HET_CLS', text: 'Close', icon: 'fa fa-rectangle-xmark' }
        ],
        onClick:function(event){
            switch(event.target){
                case 'HET_SAV':
                    let new_data = html_editor.getData();
                    let doc_pass = index.file[index.actual_file].pass;
                    let doc_uuid = index.actual_file;
                    procedure_save(doc_pass,doc_uuid,new_data,(res,ret)=>{
                        if(res==false){ w2popup.open({title:'Error',body:'Failure saving file: '+ret.toString()}); }
                        html_editor.showNotification('Saved');
                    });
                    break;
                case 'HET_LOK':
                    
                    break;
                case 'HET_CLS':
                    document.title = 'Procyon Test';
                    html_editor_hide();
                    form_main();
                    break;
            }
        }
    });
        html_editor_layout.html('top',html_editor_toolbar);
        html_editor_layout.render($('#cked')[0]);
        let hel_main = html_editor_layout.el('main');
 */   

        // CKE
/*        CKEDITOR.config.resize_enabled=false;
        var html_editor=CKEDITOR.appendTo(hel_main);
            html_editor.on('instanceReady',(evt)=>{
                html_editor.resize(hel_main.clientWidth,hel_main.clientHeight);
            });
        window.onresize=(evt)=>{
            setTimeout(()=>{ // Race condition?
                html_editor.resize(hel_main.clientWidth,hel_main.clientHeight)
            },250);
        };
        function html_editor_show(){
            $('#cked')[0].style['opacity']=1;
            $('#cked')[0].style['pointer-events']='auto';
        }
        function html_editor_hide(){
            $('#cked')[0].style['opacity']=0;
            $('#cked')[0].style['pointer-events']='none';
        }*/

    function err_popup(msg){
        webix.message({text:msg,type:"error",expire: 2000});
    }

    function form_create_index(){
        webix.ui({ id:"form_ci", view:"layout", type:"space", responsive:true, rows:[{
            view:"label", label:"Create New Index", align:"center"
        },{cols:[
            {width:10},
            { view:"form",
                elements:[
                    { view:"text", type:"password", name:"pass", labelWidth:150, label:"New Password" },
                    { view:"text", type:"password", name:"pas2", labelWidth:150, label:"New Password Check" },
                    { view:"button", value:"create", click:act_ci }
                ]
            },
            {width:10}
        ]},{}]});

        function act_ci(id){
            let form_data=this.getParentView().getValues();
            if(form_data['pass'].length<8) { err_popup('Password too short'); return false; }
            if(form_data['pass']!=form_data['pas2']) { err_popup('Password mismatch'); return false; }

            procedure_save(form_data['pass'],uuid_index,index,(res,ret)=>{
               if(res==false){ err_popup(ret.toString()); return false; }
               $$('form_ci').destructor();
               form_decode_index();
            });
        }
    }
    function form_decode_index(){
        webix.ui({ id:"form_di", view:"layout", type:"space", responsive:true, rows:[{
            view:"label", label:"Decode Index", align:"center"
        },{cols:[
            {width:10},
            {view:"form",
                elements:[
                    { view:"text", type:"password", name:"pass", label:"Password" },
                    { view:"button", value:"Decode", click:act_di }
                ]
            },
            {width:10}
        ]},{}]});

        function act_di(id){
            let form_data=this.getParentView().getValues();
            if(form_data['pass']==undefined) { err_popup('Fill Password'); return false; }
            procedure_load(form_data['pass'],uuid_index,(res,ret)=>{
                if(res==false) { err_popup(ret.toString()); return false; }
                index=ret;
                index_pass=form_data['pass'];
                $$('form_di').destructor();
                form_main();
            });
        };
	}

    function form_main(){
        webix.ui({ id:"form_main", view:"layout", type:"space", responsive:true, rows:[
            {view:"toolbar", cols:[
                { view:"button", label:"New Section", type:"icon", icon:"fa fa-folder-plus", id:"btn_ns", click:act_fm },
                { view:"button", label:"New Note", type:"icon", icon:"fa fa-file", id:"btn_nn", click:act_fm },
                { view:"button", label:"Upload File", type:"icon", icon:"fa fa-file-arrow-up", id:"btn_uf", click:act_fm },
                {},
                { view:"button", label:"Lock Screen", type:"icon", icon:"fa fa-lock", id:"btn_ls", click:act_fm },
                { view:"button", label:"Options", type:"icon", icon:"fa fa-gear", id:"btn_op", click:act_fm },
            ]},
            {cols:[
                { view:"datatable", id:"main_sect", scrollX:false, width:200, columns:[
                    {id:"data1",header:"Section",fillspace:true}
                ]},
                { view:"resizer" },
                { view:"datatable", id:"main_file", scrollX:false, columns:[
                    {id:"data1",header:'File',fillspace:true},
                    {id:"data2",header:'Modified', width:150 },
                    {id:"data3",header:'Size'}
                ]}
            ]}
        ]});

        let sect_data=index.section.map((e)=>{return[e,e];});
        $$('main_sect').parse({data:sect_data},'jsarray');

        let file_data=Object.keys(index.file)
            .filter((u)=>index.file[u].sect==index.actual_section)
            .map((u)=>[u,index.file[u]['name'],index.file[u]['date'],humanFileSize(index.file[u]['size'])]);
        $$('main_file').parse({data:file_data},'jsarray');

        function act_fm(id){
            switch(id){
                case 'btn_ns': $$('form_main').destructor(); break;
                case 'btn_nn': $$('form_main').destructor(); form_new_note(); break;
                case 'btn_uf': $$('form_main').destructor(); break;
                case 'btn_ls': $$('form_main').destructor(); break;
                case 'btn_op': $$('form_main').destructor(); break;
            }
        }
    }

	function form_new_note(){
        webix.ui({ id:"form_cn", view:"layout", type:"space", responsive:true, rows:[
            { view:"label", label:"Create New Note", align:"center" },
            { view:"form", elements:[
                { view:"text", name:"sect", label:"Section", labelWidth:90, value:index.actual_section, disabled:true },
                { view:"text", name:"name", label:"Note Name", labelWidth:90 },
                {cols:[
                    { view:"button", value:"cancel", id:"btn_cc", click:act_cn },
                    { view:"button", value:"create", id:"btn_ct", click:act_cn }
                ]}
            ]}
        ]});

        function act_cn(id){
            switch(id){
                case 'btn_cc': $$('form_cn').destructor(); form_main(); break;
                case 'btn_ct':
                    let form_data=this.getParentView().getParentView().getValues();
                    if(form_data['name']==''){ err_popup('Name too short'); return false; }
                    procedure_newf(index.actual_section,form_data['name']+'.html',(res,ret)=>{
                        if(res==false){ err_popup('Unable to create note: '+ret.toString()); return false; }
                        $$('form_cn').destructor(); form_main();
                    });                
                    break;
            }
        }
	}

    function form_html_editor(u){
        let doc_reg = index.file[u];
        index.actual_file=u;
        document.title = 'PT - '+doc_reg.name;

        procedure_load(doc_reg.pass,u,(res,ret)=>{
            if(res==false){ w2popup.open({title:'Error',body:'Failure loading file: '+ret.toString()}); }

            html_editor_layout.set('top',{title:doc_reg.name});
            html_editor_layout.refresh('top');
            html_editor.setData(ret);
            html_editor_show();
        });
    }

    // Startup
    localforage.config({driver:localforage.INDEXEDDB,name:'procyontest',version:1.0,storeName:'objects'});
    localforage.keys().then(function(keys){
        if(keys.includes(uuid_index))
             form_decode_index();
        else form_create_index();
    }).catch(function(err){
        err_popup(err);
    });
}();