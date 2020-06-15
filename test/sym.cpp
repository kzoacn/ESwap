#include <emp-tool/emp-tool.h>
#include "ESwap/ESwap.h" 
using namespace emp;
using namespace std;


int port, party;
NetIO * io;
CircuitFile aes("/home/kzoacn/emp-all/ESwap/files/AES-non-expanded.txt");
  

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

void expand(block *exp,block key){ 
    AES_KEY aes_key;
    int cur=0;
    AES_set_encrypt_key(key,&aes_key);
    for(int i=0;i<11;i++){
        for(int j=0;j<16;j++){
            unsigned char c=*(((unsigned char*)&aes_key.rd_key[i])+15-j);
            for(int k=0;k<8;k++)
                exp[cur++]=(c>>(7-k)&1) ? one_block() : zero_block();
        }    
    }
}
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

int main(int argc, char** argv) {
	//parse_party_and_port(argv, &party, &port);
	//io = new NetIO(party==PROVER ? nullptr : "127.0.0.1", port);
    
	//setup_arithmetic_zk(io, party);


	/*if(!judge(io,party,NULL,ez)){
		error("ez failed");
		return 0;
	}
    */

   block key,blk;
   key=one_block();
   blk=one_block();
   ((char*)&blk)[5]='4';
   block pla=blk;
   AES_KEY aes_key;
   AES_set_encrypt_key(key,&aes_key);
 
   AES_ecb_encrypt_blks(&blk,1,&aes_key);
   printBlock(blk);
   

   CircuitExecution::circ_exec=new AriPlainEva();

    block out[256],in1[128],in2[128];
    memset(out,0,sizeof out);
    to_bits(in1,pla);
    //memset(in1,0,sizeof in1);
    //memset(in2,0,sizeof in2); 
    for(int i=0;i<128;i++)
        in2[i]=one_block();

    aes.compute(out,in1,in2);


    string st;
    for(int i=0;i<128;i++){
        st+= (get_val(out[i])&1)+'0';
    }
    cout<< to_hex(st);

    

	//puts("Yes");

	delete io;
}
