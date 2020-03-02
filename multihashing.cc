#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include <nan.h>
#include <stdexcept>

//#if (defined(__AES__) && (__AES__ == 1)) || defined(__APPLE__) || defined(__ARM_ARCH)
//#else
//#define _mm_aeskeygenassist_si128(a, b) a
//#define _mm_aesenc_si128(a, b) a
//#endif

#include "crypto/common/VirtualMemory.h"
#include "crypto/cn/CnCtx.h" 
#include "crypto/cn/CnHash.h"
#include "crypto/randomx/randomx.h"
#include "crypto/defyx/defyx.h"

extern "C" {
#include "crypto/defyx/KangarooTwelve.h"
#include "crypto/randomx/blake2/blake2.h"
#include "c29/portable_endian.h" // for htole32/64
#include "c29/int-util.h"
}

#include "c29.h"

#if (defined(__AES__) && (__AES__ == 1)) || (defined(__ARM_FEATURE_CRYPTO) && (__ARM_FEATURE_CRYPTO == 1))
  #define SOFT_AES false
  #if defined(CPU_INTEL)
    #warning Using IvyBridge assembler implementation
    #define ASM_TYPE xmrig::Assembly::INTEL
  #elif defined(CPU_AMD)
    #warning Using Ryzen assembler implementation
    #define ASM_TYPE xmrig::Assembly::RYZEN
  #elif defined(CPU_AMD_OLD)
    #warning Using Bulldozer assembler implementation
    #define ASM_TYPE xmrig::Assembly::BULLDOZER
  #elif !defined(__ARM_ARCH)
    #error Unknown ASM implementation!
  #endif
#else
  #warning Using software AES
  #define SOFT_AES true
#endif

#define FN(algo)  xmrig::CnHash::fn(xmrig::Algorithm::algo, SOFT_AES ? xmrig::CnHash::AV_SINGLE_SOFT : xmrig::CnHash::AV_SINGLE, xmrig::Assembly::NONE)
#if defined(ASM_TYPE)
  #define FNA(algo) xmrig::CnHash::fn(xmrig::Algorithm::algo, SOFT_AES ? xmrig::CnHash::AV_SINGLE_SOFT : xmrig::CnHash::AV_SINGLE, ASM_TYPE)
#else
  #define FNA(algo) xmrig::CnHash::fn(xmrig::Algorithm::algo, SOFT_AES ? xmrig::CnHash::AV_SINGLE_SOFT : xmrig::CnHash::AV_SINGLE, xmrig::Assembly::NONE)
#endif

const size_t max_mem_size = 4 * 1024 * 1024;
xmrig::VirtualMemory mem(max_mem_size, true, false, 0, 4096);
static struct cryptonight_ctx* ctx = nullptr;
static randomx_cache* rx_cache[xmrig::Algorithm::Id::MAX] = {nullptr};
static randomx_vm* rx_vm[xmrig::Algorithm::Id::MAX] = {nullptr};
//static xmrig::Algorithm::Id rx_variant = xmrig::Algorithm::Id::MAX;
static uint8_t rx_seed_hash[xmrig::Algorithm::Id::MAX][32] = {};

struct InitCtx {
    InitCtx() {
        xmrig::CnCtx::create(&ctx, mem.scratchpad(), max_mem_size, 1);
    }
} s;

void init_rx(const uint8_t* seed_hash_data, xmrig::Algorithm::Id algo) {
    bool update_cache = false;
    if (!rx_cache[algo]) {
        rx_cache[algo] = randomx_alloc_cache(static_cast<randomx_flags>(RANDOMX_FLAG_JIT | RANDOMX_FLAG_LARGE_PAGES));
        if (!rx_cache[algo]) {
            rx_cache[algo] = randomx_alloc_cache(RANDOMX_FLAG_JIT);
        }
        update_cache = true;
    }
    else if (memcmp(rx_seed_hash[algo], seed_hash_data, sizeof(rx_seed_hash[0])) != 0) {
        update_cache = true;
    }

    //if (algo != rx_variant) {
        switch (algo) {
            case 0:
                randomx_apply_config(RandomX_MoneroConfig);
                break;
            case 1:
                randomx_apply_config(RandomX_ScalaConfig);
                break;
            case 2:
                randomx_apply_config(RandomX_ArqmaConfig);
                break;
            case 17:
                randomx_apply_config(RandomX_WowneroConfig);
                break;
            case 18:
                randomx_apply_config(RandomX_LokiConfig);
                break;
            case 19:
                randomx_apply_config(RandomX_VConfig);
                break;
            case 20:
                randomx_apply_config(RandomX_KevaConfig);
                break;
            default:
                throw std::domain_error("Unknown RandomX algo");
        }
        //rx_variant = algo;
        //update_cache = true;
    //}

    if (update_cache) {
        memcpy(rx_seed_hash[algo], seed_hash_data, sizeof(rx_seed_hash[0]));
        randomx_init_cache(rx_cache[algo], rx_seed_hash[algo], sizeof(rx_seed_hash[0]));
        if (rx_vm[algo]) {
            randomx_vm_set_cache(rx_vm[algo], rx_cache[algo]);
        }
    }

    if (!rx_vm[algo]) {
        int flags = RANDOMX_FLAG_LARGE_PAGES | RANDOMX_FLAG_JIT;
#if !SOFT_AES
        flags |= RANDOMX_FLAG_HARD_AES;
#endif

        rx_vm[algo] = randomx_create_vm(static_cast<randomx_flags>(flags), rx_cache[algo], nullptr, mem.scratchpad());
        if (!rx_vm[algo]) {
            rx_vm[algo] = randomx_create_vm(static_cast<randomx_flags>(flags - RANDOMX_FLAG_LARGE_PAGES), rx_cache[algo], nullptr, mem.scratchpad());
        }
    }
}

#define THROW_ERROR_EXCEPTION(x) Nan::ThrowError(x)

void callback(char* data, void* hint) {
    free(data);
}

using namespace node;
using namespace v8;
using namespace Nan;

NAN_METHOD(randomx) {
    if (info.Length() < 2) return THROW_ERROR_EXCEPTION("You must provide two arguments.");

    Local<Object> target = info[0]->ToObject();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

    Local<Object> seed_hash = info[1]->ToObject();
    if (!Buffer::HasInstance(seed_hash)) return THROW_ERROR_EXCEPTION("Argument 2 should be a buffer object.");
    if (Buffer::Length(seed_hash) != sizeof(rx_seed_hash[0])) return THROW_ERROR_EXCEPTION("Argument 2 size should be 32 bytes.");

    int algo = 0;
    if (info.Length() >= 3) {
        if (!info[2]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 3 should be a number");
        algo = Nan::To<int>(info[2]).FromMaybe(0);
    }

    try {
        init_rx(reinterpret_cast<const uint8_t*>(Buffer::Data(seed_hash)), static_cast<xmrig::Algorithm::Id>(algo));
    } catch (const std::domain_error &e) {
        return THROW_ERROR_EXCEPTION(e.what());
    }

    char output[32];
    switch (algo) {
      case 1:  defyx_calculate_hash  (rx_vm[algo], reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output));
               break;
      default: randomx_calculate_hash(rx_vm[algo], reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output));
    }

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
    info.GetReturnValue().Set(returnValue);
}


static xmrig::cn_hash_fun get_cn_fn(const int algo) {
  switch (algo) {
    case 0:  return FN(CN_0);
    case 1:  return FN(CN_1);
    case 4:  return FN(CN_FAST);
    case 6:  return FN(CN_XAO);
    case 7:  return FN(CN_RTO);
    case 8:  return FNA(CN_2);
    case 9:  return FNA(CN_HALF);
    case 11: return FN(CN_GPU);
    case 13: return FNA(CN_R);
    case 14: return FNA(CN_RWZ);
    case 15: return FNA(CN_ZLS);
    case 16: return FNA(CN_DOUBLE);
    default: return FN(CN_1);
  }
}

static xmrig::cn_hash_fun get_cn_lite_fn(const int algo) {
  switch (algo) {
    case 0:  return FN(CN_LITE_0);
    case 1:  return FN(CN_LITE_1);
    default: return FN(CN_LITE_1);
  }
}

static xmrig::cn_hash_fun get_cn_heavy_fn(const int algo) {
  switch (algo) {
    case 0:  return FN(CN_HEAVY_0);
    case 1:  return FN(CN_HEAVY_XHV);
    case 2:  return FN(CN_HEAVY_TUBE);
    default: return FN(CN_HEAVY_0);
  }
}

static xmrig::cn_hash_fun get_cn_pico_fn(const int algo) {
  switch (algo) {
    case 0:  return FNA(CN_PICO_0);
    default: return FNA(CN_PICO_0);
  }
}
static xmrig::cn_hash_fun get_argon2_fn(const int algo) {
  switch (algo) {
    case 0:  return FN(AR2_CHUKWA);
    case 1:  return FN(AR2_WRKZ);
    default: return FN(AR2_CHUKWA);
  }
}

NAN_METHOD(cryptonight) {
    if (info.Length() < 1) return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

    int algo = 0;
    uint64_t height = 0;
    bool height_set = false;

    if (info.Length() >= 2) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        algo = Nan::To<int>(info[1]).FromMaybe(0);
    }

    if (info.Length() >= 3) {
        if (!info[2]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 3 should be a number");
        height = Nan::To<uint32_t>(info[2]).FromMaybe(0);
        height_set = true;
    }

    if ((algo == 12 || algo == 13) && !height_set) return THROW_ERROR_EXCEPTION("CryptonightR requires block template height as Argument 3");

    const xmrig::cn_hash_fun fn = get_cn_fn(algo);

    char output[32];
    fn(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
    info.GetReturnValue().Set(returnValue);
}

NAN_METHOD(cryptonight_light) {
    if (info.Length() < 1) return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

    int algo = 0;
    uint64_t height = 0;

    if (info.Length() >= 2) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        algo = Nan::To<int>(info[1]).FromMaybe(0);
    }

    if (info.Length() >= 3) {
        if (!info[2]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 3 should be a number");
        height = Nan::To<unsigned int>(info[2]).FromMaybe(0);
    }

    const xmrig::cn_hash_fun fn = get_cn_lite_fn(algo);

    char output[32];
    fn(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
    info.GetReturnValue().Set(returnValue);
}

NAN_METHOD(cryptonight_heavy) {
    if (info.Length() < 1) return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

    int algo = 0;
    uint64_t height = 0;

    if (info.Length() >= 2) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        algo = Nan::To<int>(info[1]).FromMaybe(0);
    }

    if (info.Length() >= 3) {
        if (!info[2]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 3 should be a number");
        height = Nan::To<unsigned int>(info[2]).FromMaybe(0);
    }


    const xmrig::cn_hash_fun fn = get_cn_heavy_fn(algo);

    char output[32];
    fn(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
    info.GetReturnValue().Set(returnValue);
}

NAN_METHOD(cryptonight_pico) {
    if (info.Length() < 1) return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

    int algo = 0;

    if (info.Length() >= 2) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        algo = Nan::To<int>(info[1]).FromMaybe(0);
    }

    const xmrig::cn_hash_fun fn = get_cn_pico_fn(algo);

    char output[32];
    fn(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, 0);

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
    info.GetReturnValue().Set(returnValue);
}

NAN_METHOD(argon2) {
    if (info.Length() < 1) return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

    int algo = 0;

    if (info.Length() >= 2) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        algo = Nan::To<int>(info[1]).FromMaybe(0);
    }

    const xmrig::cn_hash_fun fn = get_argon2_fn(algo);

    char output[32];
    fn(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, 0);

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
    info.GetReturnValue().Set(returnValue);
}

NAN_METHOD(k12) {
    if (info.Length() < 1) return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

    char output[32];
    KangarooTwelve((const unsigned char *)Buffer::Data(target), Buffer::Length(target), (unsigned char *)output, 32, 0, 0);

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
    info.GetReturnValue().Set(returnValue);
}

static void setsipkeys(const char *keybuf,siphash_keys *keys) {
	keys->k0 = htole64(((uint64_t *)keybuf)[0]);
	keys->k1 = htole64(((uint64_t *)keybuf)[1]);
	keys->k2 = htole64(((uint64_t *)keybuf)[2]);
	keys->k3 = htole64(((uint64_t *)keybuf)[3]);
}

static void c29_setheader(const char *header, const uint32_t headerlen, siphash_keys *keys) {
	char hdrkey[32];
	rx_blake2b((void *)hdrkey, sizeof(hdrkey), (const void *)header, headerlen, 0, 0);
	setsipkeys(hdrkey,keys);
}

NAN_METHOD(c29s) {
	if (info.Length() != 2) return THROW_ERROR_EXCEPTION("You must provide 2 arguments: header, ring");
	
	char * input = Buffer::Data(info[0]);
	uint32_t input_len = Buffer::Length(info[0]);

	siphash_keys keys;
	c29_setheader(input,input_len,&keys);
	
	Local<Array> ring = Local<Array>::Cast(info[1]);

	uint32_t edges[PROOFSIZE];
	for (uint32_t n = 0; n < PROOFSIZE; n++)
		edges[n]=ring->Get(n)->Uint32Value(Nan::GetCurrentContext()).FromJust();
	
	int retval = c29s_verify(edges,&keys);

	info.GetReturnValue().Set(Nan::New<Number>(retval));
}

NAN_METHOD(c29v) {
	if (info.Length() != 2) return THROW_ERROR_EXCEPTION("You must provide 2 arguments: header, ring");
	
	char * input = Buffer::Data(info[0]);
	uint32_t input_len = Buffer::Length(info[0]);

	siphash_keys keys;
	c29_setheader(input,input_len,&keys);

	Local<Array> ring = Local<Array>::Cast(info[1]);

	uint32_t edges[PROOFSIZE];
	for (uint32_t n = 0; n < PROOFSIZE; n++)
		edges[n]=ring->Get(n)->Uint32Value(Nan::GetCurrentContext()).FromJust();
	
	int retval = c29v_verify(edges,&keys);

	info.GetReturnValue().Set(Nan::New<Number>(retval));
}

NAN_METHOD(c29_cycle_hash) {
	if (info.Length() != 1) return THROW_ERROR_EXCEPTION("You must provide 1 argument:ring");
	
	Local<Array> ring = Local<Array>::Cast(info[0]);

	uint8_t hashdata[116]; // PROOFSIZE*EDGEBITS/8
	memset(hashdata, 0, 116);

	int bytepos = 0;
	int bitpos = 0;
	for(int i = 0; i < PROOFSIZE; i++){

		uint32_t node = ring->Get(i)->Uint32Value(Nan::GetCurrentContext()).FromJust();

		for(int j = 0; j < EDGEBITS; j++) {
			
			if((node >> j) & 1U)
				hashdata[bytepos] |= 1UL << bitpos;

			bitpos++;
			if(bitpos==8) {
				bitpos=0;bytepos++;
			}
		}
	}

	unsigned char cyclehash[32];
	rx_blake2b((void *)cyclehash, sizeof(cyclehash), (uint8_t *)hashdata, sizeof(hashdata), 0, 0);
	
	unsigned char rev_cyclehash[32];
	for(int i = 0; i < 32; i++)
		rev_cyclehash[i] = cyclehash[31-i];
	
	v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)rev_cyclehash, 32).ToLocalChecked();
	info.GetReturnValue().Set(returnValue);
}


NAN_MODULE_INIT(init) {
    Nan::Set(target, Nan::New("cryptonight").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(cryptonight)).ToLocalChecked());
    Nan::Set(target, Nan::New("cryptonight_light").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(cryptonight_light)).ToLocalChecked());
    Nan::Set(target, Nan::New("cryptonight_heavy").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(cryptonight_heavy)).ToLocalChecked());
    Nan::Set(target, Nan::New("cryptonight_pico").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(cryptonight_pico)).ToLocalChecked());
    Nan::Set(target, Nan::New("randomx").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(randomx)).ToLocalChecked());
    Nan::Set(target, Nan::New("argon2").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(argon2)).ToLocalChecked());
    Nan::Set(target, Nan::New("k12").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(k12)).ToLocalChecked());
    Nan::Set(target, Nan::New("c29s").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(c29s)).ToLocalChecked());
    Nan::Set(target, Nan::New("c29v").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(c29v)).ToLocalChecked());
    Nan::Set(target, Nan::New("c29_cycle_hash").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(c29_cycle_hash)).ToLocalChecked());
}

NODE_MODULE(cryptonight, init)

