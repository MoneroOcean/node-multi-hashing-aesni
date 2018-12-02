#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include <nan.h>

//#if (defined(__AES__) && (__AES__ == 1)) || defined(__APPLE__) || defined(__ARM_ARCH)
//#else
//#define _mm_aeskeygenassist_si128(a, b) a
//#define _mm_aesenc_si128(a, b) a
//#endif

#if defined(__ARM_ARCH)
#define XMRIG_ARM 1
#include "xmrig/crypto/CryptoNight_arm.h"
#else
#include "xmrig/crypto/CryptoNight_x86.h"
#endif

#if (defined(__AES__) && (__AES__ == 1)) || (defined(__ARM_FEATURE_CRYPTO) && (__ARM_FEATURE_CRYPTO == 1))
#define SOFT_AES false
#else
#warning Using software AES
#define SOFT_AES true
#endif

static struct cryptonight_ctx* ctx = NULL;

void init_ctx() {
    if (ctx) return;
    ctx = static_cast<cryptonight_ctx *>(_mm_malloc(sizeof(cryptonight_ctx), 16));
    ctx->memory = static_cast<uint8_t *>(_mm_malloc(xmrig::CRYPTONIGHT_HEAVY_MEMORY, 4096));
}

#define THROW_ERROR_EXCEPTION(x) Nan::ThrowError(x)

void callback(char* data, void* hint) {
    free(data);
}

using namespace node;
using namespace v8;
using namespace Nan;

NAN_METHOD(cryptonight) {
    if (info.Length() < 1) return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

    int variant = 0;

    if (info.Length() >= 2) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        variant = Nan::To<int>(info[1]).FromMaybe(0);
    }

    char output[32];
    init_ctx();
    switch (variant) {
       case 0:  cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_0>  (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx);
                break;
       case 1:  cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_1>  (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx);
                break;
       case 3:  cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_XTL>(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx);
                break;
       case 4:  cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_MSR>(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx);
                break;
       case 6:  cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_XAO>(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx);
                break;
       case 7:  cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_RTO>(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx);
                break;
       case 8:
#if !SOFT_AES && defined(CPU_INTEL)
                #warning Using IvyBridge assembler implementation
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_2, xmrig::ASM_INTEL> (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx);
#elif !SOFT_AES && defined(CPU_AMD)
                #warning Using Ryzen assembler implementation
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_2, xmrig::ASM_RYZEN> (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx);
#else
                cryptonight_single_hash    <xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_2>         (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx);
#endif
                break;
       default: cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_1>  (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx);
    }

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
    info.GetReturnValue().Set(returnValue);
}

NAN_METHOD(cryptonight_upx) {
    if (info.Length() < 1) return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

    int variant = 0;

    if (info.Length() >= 2) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        variant = Nan::To<int>(info[1]).FromMaybe(0);
    }

    char output[32];
    init_ctx();
    switch (variant) {
       case 0:  cryptonight_single_hash<xmrig::CRYPTONIGHT_UPX, SOFT_AES, xmrig::VARIANT_0>(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx);
                break;
       case 1:  cryptonight_single_hash<xmrig::CRYPTONIGHT_UPX, SOFT_AES, xmrig::VARIANT_1>(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx);
                break;
       default: cryptonight_single_hash<xmrig::CRYPTONIGHT_UPX, SOFT_AES, xmrig::VARIANT_1>(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx);
    }

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
    info.GetReturnValue().Set(returnValue);
}

NAN_METHOD(cryptonight_light) {
    if (info.Length() < 1) return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

    int variant = 0;

    if (info.Length() >= 2) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        variant = Nan::To<int>(info[1]).FromMaybe(0);
    }

    char output[32];
    init_ctx();
    switch (variant) {
       case 0:  cryptonight_single_hash<xmrig::CRYPTONIGHT_LITE, SOFT_AES, xmrig::VARIANT_0>(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx);
                break;
       case 1:  cryptonight_single_hash<xmrig::CRYPTONIGHT_LITE, SOFT_AES, xmrig::VARIANT_1>(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx);
                break;
       default: cryptonight_single_hash<xmrig::CRYPTONIGHT_LITE, SOFT_AES, xmrig::VARIANT_1>(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx);
    }

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
    info.GetReturnValue().Set(returnValue);
}

NAN_METHOD(cryptonight_heavy) {
    if (info.Length() < 1) return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

    int variant = 0;

    if (info.Length() >= 2) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        variant = Nan::To<int>(info[1]).FromMaybe(0);
    }

    char output[32];
    init_ctx();
    switch (variant) {
       case 0:  cryptonight_single_hash<xmrig::CRYPTONIGHT_HEAVY, SOFT_AES, xmrig::VARIANT_0   >(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx);
                break;
       case 1:  cryptonight_single_hash<xmrig::CRYPTONIGHT_HEAVY, SOFT_AES, xmrig::VARIANT_XHV >(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx);
                break;
       case 2:  cryptonight_single_hash<xmrig::CRYPTONIGHT_HEAVY, SOFT_AES, xmrig::VARIANT_TUBE>(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx);
                break;
       default: cryptonight_single_hash<xmrig::CRYPTONIGHT_HEAVY, SOFT_AES, xmrig::VARIANT_0   >(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx);
    }

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
    info.GetReturnValue().Set(returnValue);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////

class CCryptonightAsync : public Nan::AsyncWorker {

    private:

        struct cryptonight_ctx* m_ctx;
        const char* const m_input;
        const uint32_t m_input_len;
        const int m_variant;
        char m_output[32];

    public:

        CCryptonightAsync(Nan::Callback* const callback, const char* const input, const uint32_t input_len, const int variant)
            : Nan::AsyncWorker(callback), m_ctx(static_cast<cryptonight_ctx *>(_mm_malloc(sizeof(cryptonight_ctx), 16))),
              m_input(input), m_input_len(input_len), m_variant(variant) {
            m_ctx->memory = static_cast<uint8_t *>(_mm_malloc(xmrig::CRYPTONIGHT_MEMORY, 4096));
        }

        ~CCryptonightAsync() {
            _mm_free(m_ctx->memory);
            _mm_free(m_ctx);
        }

        void Execute () {
            switch (m_variant) {
                case 0:  cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_0>  (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx);
                         break;
                case 1:  cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_1>  (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx);
                         break;
                case 3:  cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_XTL>(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx);
                         break;
                case 4:  cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_MSR>(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx);
                         break;
                case 6:  cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_XAO>(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx);
                         break;
                case 7:  cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_RTO>(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx);
                         break;
                case 8:
#if !SOFT_AES && defined(CPU_INTEL)
                         cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_2, xmrig::ASM_INTEL> (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx);
#elif !SOFT_AES && defined(CPU_AMD)
                         cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_2, xmrig::ASM_RYZEN> (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx);
#else
                         cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_2>             (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx);
#endif
                         break;
                default: cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_1>  (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx);
            }
        }

        void HandleOKCallback () {
            Nan::HandleScope scope;

            v8::Local<v8::Value> argv[] = {
                Nan::Null(),
                v8::Local<v8::Value>(Nan::CopyBuffer(m_output, 32).ToLocalChecked())
            };
            callback->Call(2, argv, async_resource);
        }
};

NAN_METHOD(cryptonight_async) {
    if (info.Length() < 2) return THROW_ERROR_EXCEPTION("You must provide at least two arguments.");

    Local<Object> target = info[0]->ToObject();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    int variant = 0;

    int callback_arg_num;
    if (info.Length() >= 3) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        variant = Nan::To<int>(info[1]).FromMaybe(0);
        callback_arg_num = 2;
    } else {
        callback_arg_num = 1;
    }

    Callback *callback = new Nan::Callback(info[callback_arg_num].As<v8::Function>());
    Nan::AsyncQueueWorker(new CCryptonightAsync(callback, Buffer::Data(target), Buffer::Length(target), variant));
}


class CCryptonightUPXAsync : public Nan::AsyncWorker {

    private:

        struct cryptonight_ctx* m_ctx;
        const char* const m_input;
        const uint32_t m_input_len;
        const int m_variant;
        char m_output[32];

    public:

        CCryptonightUPXAsync(Nan::Callback* const callback, const char* const input, const uint32_t input_len, const int variant)
            : Nan::AsyncWorker(callback), m_ctx(static_cast<cryptonight_ctx *>(_mm_malloc(sizeof(cryptonight_ctx), 16))),
              m_input(input), m_input_len(input_len), m_variant(variant) {
            m_ctx->memory = static_cast<uint8_t *>(_mm_malloc(xmrig::CRYPTONIGHT_UPX_MEMORY, 4096));
        }

        ~CCryptonightUPXAsync() {
            _mm_free(m_ctx->memory);
            _mm_free(m_ctx);
        }

        void Execute () {
            switch (m_variant) {
                case 0:  cryptonight_single_hash<xmrig::CRYPTONIGHT_UPX, SOFT_AES, xmrig::VARIANT_0>(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx);
                         break;
                case 1:  cryptonight_single_hash<xmrig::CRYPTONIGHT_UPX, SOFT_AES, xmrig::VARIANT_1>(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx);
                         break;
                default: cryptonight_single_hash<xmrig::CRYPTONIGHT_UPX, SOFT_AES, xmrig::VARIANT_1>(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx);
            }
        }

        void HandleOKCallback () {
            Nan::HandleScope scope;

            v8::Local<v8::Value> argv[] = {
                Nan::Null(),
                v8::Local<v8::Value>(Nan::CopyBuffer(m_output, 32).ToLocalChecked())
            };
            callback->Call(2, argv, async_resource);
        }
};


class CCryptonightLightAsync : public Nan::AsyncWorker {

    private:

        struct cryptonight_ctx* m_ctx;
        const char* const m_input;
        const uint32_t m_input_len;
        const int m_variant;
        char m_output[32];

    public:

        CCryptonightLightAsync(Nan::Callback* const callback, const char* const input, const uint32_t input_len, const int variant)
            : Nan::AsyncWorker(callback), m_ctx(static_cast<cryptonight_ctx *>(_mm_malloc(sizeof(cryptonight_ctx), 16))),
              m_input(input), m_input_len(input_len), m_variant(variant) {
            m_ctx->memory = static_cast<uint8_t *>(_mm_malloc(xmrig::CRYPTONIGHT_LITE_MEMORY, 4096));
        }

        ~CCryptonightLightAsync() {
            _mm_free(m_ctx->memory);
            _mm_free(m_ctx);
        }

        void Execute () {
            switch (m_variant) {
                case 0:  cryptonight_single_hash<xmrig::CRYPTONIGHT_LITE, SOFT_AES, xmrig::VARIANT_0>(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx);
                         break;
                case 1:  cryptonight_single_hash<xmrig::CRYPTONIGHT_LITE, SOFT_AES, xmrig::VARIANT_1>(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx);
                         break;
                default: cryptonight_single_hash<xmrig::CRYPTONIGHT_LITE, SOFT_AES, xmrig::VARIANT_1>(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx);
            }
        }

        void HandleOKCallback () {
            Nan::HandleScope scope;

            v8::Local<v8::Value> argv[] = {
                Nan::Null(),
                v8::Local<v8::Value>(Nan::CopyBuffer(m_output, 32).ToLocalChecked())
            };
            callback->Call(2, argv, async_resource);
        }
};

NAN_METHOD(cryptonight_upx_async) {
    if (info.Length() < 2) return THROW_ERROR_EXCEPTION("You must provide at least two arguments.");

    Local<Object> target = info[0]->ToObject();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    int variant = 0;

    int callback_arg_num;
    if (info.Length() >= 3) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        variant = Nan::To<int>(info[1]).FromMaybe(0);
        callback_arg_num = 2;
    } else {
        callback_arg_num = 1;
    }

    Callback *callback = new Nan::Callback(info[callback_arg_num].As<v8::Function>());
    Nan::AsyncQueueWorker(new CCryptonightUPXAsync(callback, Buffer::Data(target), Buffer::Length(target), variant));
}

NAN_METHOD(cryptonight_light_async) {
    if (info.Length() < 2) return THROW_ERROR_EXCEPTION("You must provide at least two arguments.");

    Local<Object> target = info[0]->ToObject();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    int variant = 0;

    int callback_arg_num;
    if (info.Length() >= 3) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        variant = Nan::To<int>(info[1]).FromMaybe(0);
        callback_arg_num = 2;
    } else {
        callback_arg_num = 1;
    }

    Callback *callback = new Nan::Callback(info[callback_arg_num].As<v8::Function>());
    Nan::AsyncQueueWorker(new CCryptonightLightAsync(callback, Buffer::Data(target), Buffer::Length(target), variant));
}

class CCryptonightHeavyAsync : public Nan::AsyncWorker {

    private:

        struct cryptonight_ctx* m_ctx;
        const char* const m_input;
        const uint32_t m_input_len;
        const int m_variant;
        char m_output[32];

    public:

        CCryptonightHeavyAsync(Nan::Callback* const callback, const char* const input, const uint32_t input_len, const int variant)
            : Nan::AsyncWorker(callback), m_ctx(static_cast<cryptonight_ctx *>(_mm_malloc(sizeof(cryptonight_ctx), 16))),
              m_input(input), m_input_len(input_len), m_variant(variant) {
            m_ctx->memory = static_cast<uint8_t *>(_mm_malloc(xmrig::CRYPTONIGHT_HEAVY_MEMORY, 4096));
        }

        ~CCryptonightHeavyAsync() {
            _mm_free(m_ctx->memory);
            _mm_free(m_ctx);
        }

        void Execute () {
            switch (m_variant) {
                case 0:  cryptonight_single_hash<xmrig::CRYPTONIGHT_HEAVY, SOFT_AES, xmrig::VARIANT_0   >(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx);
                         break;
                case 1:  cryptonight_single_hash<xmrig::CRYPTONIGHT_HEAVY, SOFT_AES, xmrig::VARIANT_XHV >(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx);
                         break;
                case 2:  cryptonight_single_hash<xmrig::CRYPTONIGHT_HEAVY, SOFT_AES, xmrig::VARIANT_TUBE>(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx);
                         break;
                default: cryptonight_single_hash<xmrig::CRYPTONIGHT_HEAVY, SOFT_AES, xmrig::VARIANT_0   >(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx);
            }
        }

        void HandleOKCallback () {
            Nan::HandleScope scope;

            v8::Local<v8::Value> argv[] = {
                Nan::Null(),
                v8::Local<v8::Value>(Nan::CopyBuffer(m_output, 32).ToLocalChecked())
            };
            callback->Call(2, argv, async_resource);
        }
};

NAN_METHOD(cryptonight_heavy_async) {
    if (info.Length() < 2) return THROW_ERROR_EXCEPTION("You must provide at least two arguments.");

    Local<Object> target = info[0]->ToObject();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    int variant = 0;

    int callback_arg_num;
    if (info.Length() >= 3) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        variant = Nan::To<int>(info[1]).FromMaybe(0);
        callback_arg_num = 2;
    } else {
        callback_arg_num = 1;
    }

    Callback *callback = new Nan::Callback(info[callback_arg_num].As<v8::Function>());
    Nan::AsyncQueueWorker(new CCryptonightHeavyAsync(callback, Buffer::Data(target), Buffer::Length(target), variant));
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////

NAN_MODULE_INIT(init) {
    Nan::Set(target, Nan::New("cryptonight").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(cryptonight)).ToLocalChecked());
    Nan::Set(target, Nan::New("cryptonight_async").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(cryptonight_async)).ToLocalChecked());
    Nan::Set(target, Nan::New("cryptonight_upx").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(cryptonight_upx)).ToLocalChecked());
    Nan::Set(target, Nan::New("cryptonight_upx_async").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(cryptonight_upx_async)).ToLocalChecked());
    Nan::Set(target, Nan::New("cryptonight_light").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(cryptonight_light)).ToLocalChecked());
    Nan::Set(target, Nan::New("cryptonight_light_async").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(cryptonight_light_async)).ToLocalChecked());
    Nan::Set(target, Nan::New("cryptonight_heavy").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(cryptonight_heavy)).ToLocalChecked());
    Nan::Set(target, Nan::New("cryptonight_heavy_async").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(cryptonight_heavy_async)).ToLocalChecked());
}

NODE_MODULE(cryptonight, init)
