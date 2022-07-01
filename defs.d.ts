declare type data = Array<{content:any,algorithm:"sha256"|"sha512",key:string|number}>
declare function enc(data:data):String