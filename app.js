$(function(){

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

            let f = {
                uuid:uuidv4(),
                sect:section,
                name:name,
                date:getdate(),
                size:0,
                pass:ret
            };
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
    function err_popup(msg){
        w2popup.open({title:'Error',body:msg,actions:{Close(evt){w2popup.close()}}});
    }       

    let index_create_form = new w2form({
        name:'index_create_form',
        header:'Create new Index',
        fields:[
            {field:'pass',type:'password',required:true,html:{label:'New Password'}},
            {field:'pas2',type:'password',required:true,html:{label:'New Password Check'}}
        ],
        actions: {
            'Create':function(event){
                let form_data=this.getCleanRecord();

                if(form_data['pass']==undefined) { err_popup('Fill Password'); return false; }
                if(form_data['pas2']==undefined) { err_popup('Fill Password Check'); return false; }
                if(form_data['pass'].length<8) { err_popup('Password too short'); return false; }
                if(form_data['pass']!=form_data['pas2']) { err_popup('Password mismatch'); return false; }

                procedure_save(form_data['pass'],uuid_index,index,(res,ret)=>{
                    if(res==false){ err_popup(ret.toString()); return false; }
                    form_decode_index();
                });
            }
        }
    });
    let index_decode_form = new w2form({
        name:'index_decode_form',
        header:'Decode Index',
        fields:[
            {field:'pass',type:'password',required:true,html:{label:'Password'}}
        ],
        actions: {
            'Decode':function(event){
                let form_data=this.getCleanRecord();
                if(form_data['pass']==undefined) { err_popup('Fill Password'); return false; }
                procedure_load(form_data['pass'],uuid_index,(res,ret)=>{
                    if(res==false) { err_popup(ret.toString()); return false; }
                    index=ret;
                    index_pass=form_data['pass'];
                    form_main();
                });
            }
        }
    });

    let main_layout = new w2layout({
        name:'main_layout',
        panels: [{type:'top',size:40},{type:'left',size:150,resizable:true},{type:'main'}]
    });
        let main_toolbar = new w2toolbar({
            name:'main_toolbar',
            items: [
                { type: 'button', id: 'MT_NS', text: 'New Section', icon: 'fa fa-folder-plus' },
                { type: 'button', id: 'MT_NN', text: 'New Note', icon: 'fa fa-file' },
                { type: 'button', id: 'MT_UF', text: 'Upload File', icon: 'fa fa-file-arrow-up' },
                { type: 'spacer' },
                { type: 'button', id: 'MT_LK', text: 'Lock Screen', icon: 'fa fa-lock' },
                { type: 'button', id: 'MT_OP', text: 'Options', icon: 'fa fa-gear' }
            ],
            onClick:function(event){
                switch(event.target){
                    case 'MT_NS': break;
                    case 'MT_NN': form_new_note(); break;
                    case 'MT_UF': break;
                    case 'MT_LK': break;
                    case 'MT_OP': break;
                }
            }
        });
        let main_sidebar = new w2sidebar({
            name:'main_sidebar',
        });
        let main_grid = new w2grid({
            name:'main_grid',
            columns: [
                {field:'fname',text:'File'},
                {field:'fmodi',text:'Modified',size:25},
                {field:'fsize',text:'Size',size:10}
            ],
            onClick:(evt)=>{
                let f = index.file[evt.recid];
                let f_split = f.name.split('.');
                let f_ext = f_split[f_split.length-1].toLowerCase();
                switch(f_ext){
                    case 'html': form_html_editor(f.uuid); break;
                }
            }
        });
        main_layout.html('top',main_toolbar);
        main_layout.html('left',main_sidebar);
        main_layout.html('main',main_grid);

    let note_create_form = new w2form({
        name:'note_create_form',
        header:'Create New Note',
        record:{sect:index.actual_section},
        focus:1,
        fields:[
            {field:'sect',type:'text',required:true,html:{label:'Section'}},
            {field:'name',type:'text',required:true,html:{label:'Name'}}
        ],
        actions: {
            'Cancel':function(event){ form_main(); },
            'Create':function(event){
                let form_data=this.getCleanRecord();
                if(form_data['name']==undefined || form_data['name'].length<1){ err_popup('Name too short'); return false; }
                
                procedure_newf(index.actual_section,form_data['name']+'.html',(res,ret)=>{
                    if(res==false){ err_popup('Unable to create note: '+ret.toString()); return false; }
                    form_main();
                });
            }
        }
    }); 
        note_create_form.disable('sect');
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
    
        // CKE
        CKEDITOR.config.resize_enabled=false;
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
        }


    function form_create_index(){
        index_create_form.clear();
		index_create_form.render($('#main')[0]);
	}
    function form_decode_index(){
        index_decode_form.clear();
		index_decode_form.render($('#main')[0]);
	}

    function form_main(){
        function add_sidebar_section(sec){ main_sidebar.add([{id:sec,text:sec,icon:'fa fa-folder'}]); }
        function del_sidebar_section(sec){ main_sidebar.remove(sec); }
        function clr_sidebar_section(){ main_sidebar.get().forEach((s)=>{main_sidebar.remove(s)}) }
		function fil_sidebar_section(){ index.section.forEach((s)=>{ add_sidebar_section(s); }) }

        function add_grid_file(u){
            let f=index.file[u];
            main_grid.add({recid:f['uuid'],fname:f['name'],fmodi:f['date'],fsize:humanFileSize(f['size'])});
        }
        function del_grid_file(u){ main_grid.remove(u); }
		function clr_grid_file() { main_grid.find().forEach((u)=>{del_grid_file(u)}); }
		function fil_grid_file(){
            Object.keys(index.file)
                .filter((u)=>index.file[u].sect==index.actual_section)
                .forEach((u)=>add_grid_file(u));
        }

        clr_sidebar_section();
		clr_grid_file();

        fil_sidebar_section();
		fil_grid_file();

		main_layout.render($('#main')[0]);
    }

	function form_new_note(){
        note_create_form.clear();
        note_create_form.render($('#main')[0]);

        note_create_form.record['sect']=index.actual_section;
        note_create_form.refresh();
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
});