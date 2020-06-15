#include <emp-tool/emp-tool.h>
#include "ESwap/ESwap.h"
#include "ESwap/json.hpp"
using namespace nlohmann;
using namespace emp;
using namespace std;


int port, party;
NetIO * io;
CircuitFile sha("./files/sha-256.txt");
CircuitFile aes("./files/AES-non-expanded.txt");

void to_bits(block *out, block in)
{
    int cur=0;
    for (int j = 0; j < 16; j++)
    {
        unsigned char c = *(((unsigned char *)&in) + j);
        for (int k = 0; k < 8; k++)
        {
            out[cur++] = (c >> (7 - k) & 1) ? one_block() : zero_block();
        }
    }
}
void from_bits(block &out, block *in)
{
    int cur=0;
    for (int j = 0; j < 16; j++)
    {
        unsigned char *c = (((unsigned char *)&out) + j);
        *c=0;
        for (int k = 0; k < 8; k++)
        {
            *c=*c<<1 | (get_val(in[cur++])&1);
        }
    }
}

void sha_compute(block *out,block *in,int length){
    block in1[512],in2[512];
    //string input=padding(in);
    for(int i=0;i<512;i++){
        in1[i]=zero_block();
        if(i<length)
            in1[i]=in[i];       
    }
    CircuitFile sha256=sha;
    auto t=CircuitExecution::circ_exec;
    CircuitExecution::circ_exec=new AriPlainEva();
    sha256.compute(out,in1,in2);
    CircuitExecution::circ_exec=t;
}


char to_hex(int x){
    if(x<10)
        return '0'+x;
    return 'A'+x-10;
}

string to_hex(string s){
    string ans;
    for(int i=0;i<(int)s.length();i+=4){
        int x=0;
        for(int j=0;j<4;j++)
            x=x<<1 | (s[i+j]-'0');
        ans+=to_hex(x);
    }
    return ans;
}



/*

1. send c, {Com_i} , ZK \exits k,m,r (C(m)=1 and Enc(k,m)=c and sha256(ri,ki)=Com_i )
2. Decom ri ki
3. 

*/



   block key,blk,plain_text;
    block r[128][128],k[128],com[128][256],pt[128],ci[128];
    string msg;

    block oci[128],ocom[128][256],ok[128];

struct  EOS_CTX
{
    block *pt,*k,*ci; 
    block *com[128];   
};


Bit EOS(void* _ctx){ 
    EOS_CTX *ctx=(EOS_CTX*)_ctx;
    Bit ans(true,PUBLIC);
    CircuitFile sha256=sha;
    CircuitFile aes128=aes;

    Bit cipher[128],keys[128];
    Bit plain[128],out[256];
    for(int i=0;i<128;i++){
        plain[i]=Bit(getLSB(ctx->pt[i]),PROVER);
        keys[i]=Bit(getLSB(ctx->k[i]),PROVER); 
        cipher[i]=Bit(getLSB(ctx->ci[i]),PUBLIC); 
    }

    aes128.compute((block*)out,(block*)plain,(block*)keys);
 
    for(int i=0;i<128;i++){  
        ans=ans&(out[i]==cipher[i]);
    }     


    for(int j=0;j<128;j++){
        Bit rd[512],cm[256];
        for(int i=0;i<127;i++)
            rd[i]=Bit(getLSB(r[j][i]),PROVER);
        rd[127]=keys[j];
        for(int i=128;i<512;i++)
            rd[i]=Bit(0,PUBLIC);
        for(int i=0;i<256;i++)
            cm[i]=Bit(getLSB(ctx->com[j][i]),PUBLIC);

        sha256.compute((block*)out,(block*)rd,NULL);

        for(int i=0;i<256;i++){  
            ans=ans&(out[i]==cm[i]);
        }    
    }

    
    
    
	return ans;
}

int main(int argc, char** argv) {
 	if(argc!=2){
		fprintf(stderr,"usage: ./bin/swap <config.json>\n");
		return 0;	
	}

	ifstream fin(argv[1]);
	json js;
	fin>>js;

	party=js["party"];
	port=js["port"];
	string ip=js["ip"];
	string input_file=js["input_file"];

 
	io = new NetIO(party==PROVER ? nullptr : "127.0.0.1", port);
    
	



    ifstream messsage_in(input_file);
    getline(messsage_in,msg);
    if(msg.length()*8>128){
        error("message too long");
        return 0;
    }
    
 

    PRG prng;

    //key=one_block();
    prng.random_block(&key,1);
    
   AES_KEY aes_key;
   AES_set_encrypt_key(key,&aes_key);
   blk=zero_block();
   for(int i=0;i<(int)msg.length();i++)
        ((unsigned char*)&blk)[i]=msg[i];

    plain_text=blk;
   AES_ecb_encrypt_blks(&blk,1,&aes_key);
    
    to_bits(ci,blk);
    to_bits(pt,plain_text);
    to_bits(k,key);
 


    for(int i=0;i<128;i++){
        prng.random_block(r[i],127);
        r[i][127]=k[i];
        sha_compute(com[i],r[i],128);
    }





    for(int p : vector<int>{0,1}){
        int role=(party-1+p)%2+1;
        EOS_CTX ctx; 
        ctx.pt=pt;
        ctx.k=k;
        if(role==PROVER){
            io->send_block(ci,128);
            io->flush();
            io->recv_block(oci,128);
            ctx.ci=ci;

            for(int i=0;i<128;i++){
                io->send_block(com[i],256);
                ctx.com[i]=com[i];
            }
            io->flush();
        }else{
            io->recv_block(oci,128);
            io->send_block(ci,128);
            io->flush();
            ctx.ci=oci;
        
            for(int i=0;i<128;i++){
                io->recv_block(ocom[i],256);
                ctx.com[i]=ocom[i];
            }
        }
    
        setup_arithmetic_zk(io, role);
        if(!judge(io,role,&ctx,EOS)){
            error("EOS failed");
            return 0;
        }else{
            cerr<<"ZK passed"<<endl;
        }
    }
    
    for(int p : vector<int>{0,1}){
        int role=(party-1+p)%2+1;
        for(int i=0;i<128;i++){
            block rr[128],out[256];
            if(role==PROVER){
                io->send_block(r[i],128);
                io->flush();

            }else{
                io->recv_block(rr,128);
                sha_compute(out,rr,128);
                ok[i]=rr[127];
                for(int j=0;j<256;j++){
                    if(getLSB(out[j])!=getLSB(ocom[i][j])){
                        error("Decom failed!");
                        return 0;
                    }
                }
            }
        }
    }
        block okey,oblk;
        from_bits(okey,ok);
        from_bits(oblk,oci);


        AES_set_decrypt_key(okey,&aes_key);
        AES_ecb_decrypt_blks(&oblk,1,&aes_key);

        string omsg;
        omsg.resize(16);

        for(int i=0;i<16;i++)
            omsg[i]=((char*)&oblk)[i];


        cout<<omsg<<endl;
    

    puts("Yes");

	delete io;
}
