#ifndef ARITHMETICZK_H__
#define ARITHMETICZK_H__
#include "ESwap/arithmetic_zk_gen.h"
#include "ESwap/arithmetic_zk_eva.h"
#include "ESwap/arithmetic_plain_eva.h"
#include <emp-tool/emp-tool.h>

//#ifndef THREADING

//#error "need threading"

//#endif

namespace emp {
template<typename IO>
inline void setup_arithmetic_zk(IO* io, int party) {
	if(party == VERIFIER) {
		AriPrivacyFreeGen<IO> * t = new AriPrivacyFreeGen<IO>(io);
		CircuitExecution::circ_exec = t;
		ArithmeticExecution::ari_exec=t;
		ProtocolExecution::prot_exec = new ArithmeticZKGen<IO>(io, t);
	} else {
		AriPrivacyFreeEva<IO> * t = new AriPrivacyFreeEva<IO>(io);
		CircuitExecution::circ_exec = t;
		ArithmeticExecution::ari_exec=t;
		ProtocolExecution::prot_exec = new ArithmeticZKEva<IO>(io, t);
	}
}


template<typename IO>
inline bool check_bit(IO* io,Bit &b,int party){
    if(party == VERIFIER) {
        block t;
        io->recv_block(&t,1);
		AriPrivacyFreeGen<IO>* p=(AriPrivacyFreeGen<IO> *)((void*)CircuitExecution::circ_exec);
		
        return p->isDelta(xorBlocks(t,b.bit));
    }else{
        io->send_block(&b.bit,1);
        return true;
    }
}


class LocalIO: public IOChannel<LocalIO>{ public:

	ThreadBuffer<char> *s_buffer;
	ThreadBuffer<char> *r_buffer;

	void send_data(const void * data, int len) {

		char *c=(char*)data;
		s_buffer->push(c,len);

	}
	void recv_data(void  * data, int len) {

		char *c=(char*)data;
		r_buffer->get(c,len);

	}
void flush(){}
};



AriPlainEva *plain;
ArithmeticPlainEva *plain_exec;
template<typename IO>
void preprocess(IO *io,void *ctx,Bit(*f)(void*)){

	ArithmeticExecution::ari_exec=plain;
	CircuitExecution::circ_exec=plain;
	ProtocolExecution::prot_exec = plain_exec;
	f(ctx);

}


AriPrivacyFreeEva<LocalIO> *prover;
ArithmeticZKEva<LocalIO> *prover_exec;

AriPrivacyFreeGen<LocalIO> *verifier;
ArithmeticZKGen<LocalIO> *verifier_exec;

void sim_prover(void *ctx,Bit(*f)(void*)){

	ArithmeticExecution::ari_exec=prover;
	CircuitExecution::circ_exec=prover;
	ProtocolExecution::prot_exec = prover_exec;
	f(ctx);

}
void sim_verifier(void *ctx,Bit(*f)(void*)){

	ArithmeticExecution::ari_exec=verifier;
	CircuitExecution::circ_exec=verifier;
	ProtocolExecution::prot_exec = verifier_exec;
	f(ctx);
}



template<typename IO>
bool prove(IO *io,void *ctx,Bit(*f)(void*)){
	
	

	char out_msg[Hash::DIGEST_SIZE];
	char in_msg[Hash::DIGEST_SIZE];
	Commitment Commiter;

	Com comDelta,comDeltaM,comDig;
	Decom decomDelta,decomDeltaM,decomDig;
	
	
	AriPrivacyFreeEva<IO> * a_exec = (AriPrivacyFreeEva<IO> *)ArithmeticExecution::ari_exec;
	ArithmeticZKEva<IO> * p_exec = (ArithmeticZKEva<IO> *)ProtocolExecution::prot_exec;

	io->recv_data(comDelta,sizeof(Com));
	io->recv_data(comDeltaM,sizeof(Com));


	plain=new AriPlainEva();
	plain_exec=new ArithmeticPlainEva(plain);

	ThreadBuffer<bool> *buf=new ThreadBuffer<bool>();
	plain_exec->buf=buf;
	p_exec->buf=buf;

	CountPlainEva* count=new CountPlainEva(plain);
	ArithmeticExecution::ari_exec=plain;
	CircuitExecution::circ_exec=plain;
	ProtocolExecution::prot_exec=count;
	f(ctx); 

	long long counter=count->counter;
	//std::cerr<<"size is "<<counter<<std::endl;

	std::thread pre_thread(preprocess<IO>,io,ctx,f);
	

 
	ArithmeticExecution::ari_exec=a_exec;
	CircuitExecution::circ_exec=a_exec;
	ProtocolExecution::prot_exec=p_exec;
	p_exec->all_size=counter;
	std::cerr<<"evaluating circuit"<<std::endl;
	int gid=a_exec->gid;
	a_exec->recv_h.reset();
	Bit bit=f(ctx);
	pre_thread.join();
	a_exec->is_true(bit);  

	char dig[Hash::DIGEST_SIZE];
	a_exec->eq_hash.digest(dig);
	Commiter.commit(decomDig,comDig,dig,Hash::DIGEST_SIZE);

	a_exec->recv_h.digest(in_msg);

	io->send_data(comDig,sizeof(Com));

	io->recv_data(decomDelta,sizeof(Decom));
	io->recv_data(decomDeltaM,sizeof(Decom));
	block delta,deltaM,seed;
	io->recv_data(&delta,sizeof(block));
	io->recv_data(&deltaM,sizeof(block));
	io->recv_data(&seed,sizeof(block));//TODO commit
	Commiter.open(decomDelta,comDelta,&delta,sizeof(block));	
	Commiter.open(decomDeltaM,comDeltaM,&deltaM,sizeof(block));	
	//check circuit

	ThreadBuffer<char> *s_buffer=new ThreadBuffer<char>();
	ThreadBuffer<char> *r_buffer=new ThreadBuffer<char>();

	LocalIO *lio1=new LocalIO();
	LocalIO *lio2=new LocalIO();

	lio1->s_buffer=s_buffer;
	lio1->r_buffer=r_buffer;

	lio2->s_buffer=r_buffer;
	lio2->r_buffer=s_buffer;


	plain=new AriPlainEva();
	plain_exec=new ArithmeticPlainEva(plain);
	buf=new ThreadBuffer<bool>();
	plain_exec->buf=buf;

	prover=new AriPrivacyFreeEva<LocalIO>(lio1);
	prover_exec=new ArithmeticZKEva<LocalIO>(lio1,prover);

	verifier=new AriPrivacyFreeGen<LocalIO>(lio2);
	verifier_exec=new ArithmeticZKGen<LocalIO>(lio2,verifier);

	prover->gid=gid;
	verifier->gid=gid;
	verifier->set_delta(delta,deltaM);
	prover_exec->all_size=counter;
	prover_exec->buf=buf;
	prover_exec->ot->prg.reseed(&p_exec->seed);
	verifier_exec->ot->prg.reseed(&seed);
	std::cerr<<"checking circuit"<<std::endl;
	std::thread pre_thread2(preprocess<IO>,io,ctx,f);
	std::thread thread_prover(sim_prover,ctx,f);
	std::thread thread_verifier(sim_verifier,ctx,f);

	thread_prover.join();
	thread_verifier.join();
	pre_thread2.join();


	prover->recv_h.digest(out_msg);

	if(memcmp(out_msg,in_msg,Hash::DIGEST_SIZE)!=0)
		return false;
	
	ArithmeticExecution::ari_exec=a_exec;
	CircuitExecution::circ_exec=a_exec;
	ProtocolExecution::prot_exec=p_exec;
	

	
	io->send_data(decomDig,sizeof(Decom));
	io->send_data(dig,sizeof(dig));



	delete plain;
	delete plain_exec;

	return true;
}

template<typename IO>
bool verify(IO *io,void *ctx,Bit(*f)(void*)){

	AriPrivacyFreeGen<IO> * a_exec = (AriPrivacyFreeGen<IO> *)ArithmeticExecution::ari_exec;
	ArithmeticZKGen<IO> * p_exec = (ArithmeticZKGen<IO> *)ProtocolExecution::prot_exec;
	
	Commitment Commiter;

	Com comDelta,comDeltaM,comDig;
	Decom decomDelta,decomDeltaM,decomDig;
	Commiter.commit(decomDelta,comDelta,&p_exec->gc->delta,sizeof(p_exec->gc->delta));
	Commiter.commit(decomDeltaM,comDeltaM,&p_exec->gc->mdelta,sizeof(p_exec->gc->delta));
	io->send_data(comDelta,sizeof(Com));
	io->send_data(comDeltaM,sizeof(Com));

	

	Bit bit=f(ctx); 
	a_exec->is_true(bit);

	char dig[Hash::DIGEST_SIZE];
	char oth[Hash::DIGEST_SIZE];
	a_exec->eq_hash.digest(dig);
	io->recv_data(comDig,sizeof(Com));

	io->send_data(decomDelta,sizeof(Decom));
	io->send_data(decomDeltaM,sizeof(Decom));
	io->send_data(&p_exec->gc->delta,sizeof(block));
	io->send_data(&p_exec->gc->mdelta,sizeof(block));
	io->send_data(&p_exec->seed,sizeof(block));

	io->recv_data(decomDig,sizeof(Decom));
	io->recv_data(oth,sizeof(oth));
	bool ans = Commiter.open(decomDig,comDig,oth,Hash::DIGEST_SIZE);

 
	if(memcmp(dig,oth,Hash::DIGEST_SIZE)!=0)
		return false;

	return ans;
}


template<typename IO>
bool judge(IO *io,int party,void *ctx,Bit(*f)(void*) ){
	if(party==PROVER){
		if(!prove(io,ctx,f)){
			return false;
		}
	}else{
		if(!verify(io,ctx,f)){ 
			return false;
		}
	}
	return true;
}


}
#endif
