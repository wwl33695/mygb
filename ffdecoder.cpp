#include "ffdecoder.h"
#include <unistd.h>
#include <stdio.h>

extern "C" {
#include <libavcodec/avcodec.h>
//#include <libavdevice/avdevice.h>
#include <libavformat/avformat.h>
//#include <libavfilter/avfilter.h>
#include <libavutil/avutil.h>
#include <libavutil/error.h>
#include <libswscale/swscale.h>
//#include <libavutil/pixdesc.h>
}

#ifndef USE_CAMBRICON
    #define USE_CAMBRICON
#endif

#ifdef USE_CAMBRICON

#include "cncodec.h"
#include "cnrt.h"

#define FFDECODER_CALL_CN_FUNC(x) \
{\
    int ret = x; \
    if (0 != ret)\
    {\
        printf("ERROR.%s:%u, 0x%x\n", __FILE__, __LINE__, ret);\
        return -1;\
    }\
}

#define FFDECODER_ALIGN_UP(x, a) ((x+a-1)&(~(a-1)))

CN_S32 static ShowCapability(CN_VOID)
{
    CN_VDEC_CAPABILITY_S temp_cap;
    FFDECODER_CALL_CN_FUNC(CN_MPI_VDEC_GetCapability(&temp_cap));
    printf("%-10s%-10s%-10s%-10s\n", "id", "mlu_index", "free_chn", "used_chn");
    printf("------------------------------------------------\n");
    for (CN_U32 iloop = 0; iloop < temp_cap.u32VdecDeviceNum; iloop++)
    {
        printf("%-10u%-10u%-10u%-10u\n",
               temp_cap.VdecDeviceList[iloop].u32DeviceID,
               temp_cap.VdecDeviceList[iloop].u32MluIndex,
               temp_cap.VdecDeviceList[iloop].u32FreeChannels,
               temp_cap.VdecDeviceList[iloop].u32UsedChannels);
    }
    printf("\n");
    return CN_SUCCESS;
}

// 申请解码图像输出内存
CN_S32 static MallocOutputBuffer(CN_U32 frame_num,
                          CN_U32 frame_size,
                          CN_U32 data_parallelism,
                          void **mlu_ptrs)
{
    void *param = NULL;
    int type = CNRT_MALLOC_EX_PARALLEL_FRAMEBUFFER;
    FFDECODER_CALL_CN_FUNC(cnrtAllocParam(&param));
    FFDECODER_CALL_CN_FUNC(cnrtAddParam(param, "type", sizeof(type), &type));
    FFDECODER_CALL_CN_FUNC(cnrtAddParam(param, "data_parallelism", sizeof(data_parallelism), &data_parallelism));
    FFDECODER_CALL_CN_FUNC(cnrtAddParam(param, "frame_num", sizeof(frame_num), &frame_num));
    FFDECODER_CALL_CN_FUNC(cnrtAddParam(param, "frame_size", sizeof(frame_size), &frame_size));
    FFDECODER_CALL_CN_FUNC(cnrtMallocBufferEx(mlu_ptrs, param));  // 申请MLU解码图像输出内存
    FFDECODER_CALL_CN_FUNC(cnrtDestoryParam(param));
    return CN_SUCCESS;
}

static void DecodeCallback(void *attr, uint64_t user_data)
{
    CN_VIDEO_IMAGE_INFO_S *p_image_attr = (CN_VIDEO_IMAGE_INFO_S *)attr;

    FFDecoder *that = (FFDecoder *)user_data;

#if 0
    printf("size:%u stride:%u phy:%lu vir:%lu frame:%lu buf:%lu trans:%lu delay:%lu send:%lu input:%lu\n",
            p_image_attr->u32FrameSize, p_image_attr->u32Stride[0] , p_image_attr->u64PhyAddr, p_image_attr->u64VirAddr,
            p_image_attr->u64FrameIndex, p_image_attr->u32BufIndex, p_image_attr->u64TransferUs,
            p_image_attr->u64DecodeDelayUs, p_image_attr->u64SendCallbackDelayUs, p_image_attr->u64InputUs);
#endif

    cnrtSetCurrentDevice(that->cnrt_dev);

    AVFrame *frame = av_frame_alloc();

    frame->format = AV_PIX_FMT_BGR24;
    frame->width = p_image_attr->u32Width;
    frame->height = p_image_attr->u32Height;

    for (int i = 0; i < 4; i++) {
        frame->linesize[i] = p_image_attr->u32Stride[i] * 3;
    }

    if (av_frame_get_buffer(frame, 32) != 0) {
        printf("DecodeCallback av_frame_get_buffer return error\n");
        return;
    }

    if (p_image_attr->u32Stride[0] * 3 != frame->linesize[0]) {
        printf("DecodeCallback u32Stride != linesize %u != %u\n", frame->linesize[0]);
        abort();
    }

    if (p_image_attr->u32FrameSize > 0) {
         cnrtMemcpy(frame->data[0], (void *)p_image_attr->u64VirAddr,
                    p_image_attr->u32Stride[0] * p_image_attr->u32Height * 3, CNRT_MEM_TRANS_DIR_DEV2HOST);
        // 释放MLU缓存buffer，释放后新的解码图像才可以写入此buffer
        CN_MPI_MLU_P2P_ReleaseBuffer(that->h_decoder, p_image_attr->u32BufIndex);
    } else {
        printf("DecodeCallback end\n");
        av_frame_free(&frame);
        return;
    }

    {
        std::lock_guard<std::mutex> lock(that->m_mtx_frames);
        that->m_frames.push_back(frame);

        if (that->m_frames.size() > 30) {
            printf("DecodeCallback frames count:%lu\n", that->m_frames.size());
        }
    }
}

int FFDecoder::CreateDecoder(int codec_id, int device)
{
    printf("CN_MPI_SoftWareVersion:%s\n", CN_MPI_SoftwareVersion());
    FFDECODER_CALL_CN_FUNC(CN_MPI_Init());  // cncodec sdk初始化
    FFDECODER_CALL_CN_FUNC(cnrtInit(0));  // cnrt sdk初始化
    FFDECODER_CALL_CN_FUNC(ShowCapability());  // 显示设备capability

    FFDECODER_CALL_CN_FUNC(cnrtGetDeviceHandle(&cnrt_dev, device));  // 获取device 0 的MLU设备号
    FFDECODER_CALL_CN_FUNC(cnrtSetCurrentDevice(cnrt_dev));  // 设置当前线程绑定的device

    CN_VIDEO_CODEC_TYPE_E codec_type = CN_VIDEO_CODEC_H264;

    if (codec_id == AV_CODEC_ID_MJPEG) {
        //codec_type = CN_VIDEO_CODEC_MJPEG;
        return -1;
    } else if (codec_id == AV_CODEC_ID_H264) {
        codec_type = CN_VIDEO_CODEC_H264;
    } else if (codec_id == AV_CODEC_ID_HEVC) {
        codec_type = CN_VIDEO_CODEC_HEVC;
    } else if (codec_id == AV_CODEC_ID_MPEG4) {
        codec_type = CN_VIDEO_CODEC_MPEG4;
    } else {
        return -1;
    }

    CN_VIDEO_CREATE_ATTR_S chn_attr;
    memset(&chn_attr, 0, sizeof(chn_attr));
    chn_attr.u32VdecDeviceID = device;  // 在device 0上创建解码通道
    chn_attr.enInputVideoCodec = codec_type;
    chn_attr.enVideoMode = CN_VIDEO_MODE_FRAME;//CN_VIDEO_MODE_STREAM
    chn_attr.u32MaxWidth = MAX_OUTPUT_WIDTH;  // 最大输入分辨率，只能解码此范围内的压缩数据
    chn_attr.u32MaxHeight = MAX_OUTPUT_HEIGHT;
    chn_attr.u32TargetWidth = m_width;//1920;//st->codecpar->width;  // 输出分辨率，解码图像resize到此分辨率输出
    chn_attr.u32TargetHeight = m_height;//1080;//st->codecpar->height;
    chn_attr.enOutputPixelFormat = CN_PIXEL_FORMAT_RGB24;
    chn_attr.u64UserData = (CN_U64)this;  // 设置回调函数的用户数据指针，回调函数中需要使用的数据
    chn_attr.pImageCallBack = (CN_VDEC_IMAGE_CALLBACK)DecodeCallback;

    // 申请解码图像输出内存
    // 申请8个解码图像输出内存（8个frame）
    int OUTPUT_BUFFER_NUM = 8;
    CN_U32 frame_size = chn_attr.u32TargetWidth * chn_attr.u32TargetHeight * 3;  // 计算每个RGB解码图像占用的空间 frame_size
    frame_size = FFDECODER_ALIGN_UP(frame_size, 64 * 1024);  // frame_size必须64K对齐

    FFDECODER_CALL_CN_FUNC(MallocOutputBuffer(OUTPUT_BUFFER_NUM, frame_size, 4, &mlu_ptrs));  // 申请输出内存
    CN_MLU_P2P_BUFFER_S buffers[OUTPUT_BUFFER_NUM];
    for (int iloop = 0; iloop < OUTPUT_BUFFER_NUM; iloop++)
    {
        // 计算每个frame buffer的虚拟地址和长度，填充配置信息
        buffers[iloop].addr = reinterpret_cast<CN_U64>(mlu_ptrs) + (frame_size * iloop);
        buffers[iloop].len = frame_size;
    }
    chn_attr.mluP2pAttr.buffer_num = OUTPUT_BUFFER_NUM;
    chn_attr.mluP2pAttr.p_buffers = buffers;

    // 创建通道
    FFDECODER_CALL_CN_FUNC(CN_MPI_VDEC_Create(&h_decoder, &chn_attr));

    return 0;
}

#endif //USE_CAMBRICON

FFDecoder::FFDecoder()
{
    m_ifmt_ctx = NULL;
    m_avctx = NULL;
    m_swsContext = NULL;
    m_video_index = -1;
    m_stop = false;

    m_width = -1;
    m_height = -1;

    m_useCambricon = false;
    h_decoder = 0;
    cnrt_dev = 0;
    mlu_ptrs = NULL;

    av_register_all();
    avformat_network_init();
}

FFDecoder::~FFDecoder()
{
    m_stop = true;

    if (m_avctx != NULL) {
        avcodec_free_context(&m_avctx);
        m_avctx = NULL;
    }

    if (m_ifmt_ctx != NULL) {
        avformat_close_input(&m_ifmt_ctx);
        m_ifmt_ctx = NULL;
    }

    if( m_parser )
    {
        av_parser_close(m_parser);
        m_parser = NULL;
    }
}

void FFDecoder::Stop()
{
    m_stop = true;
    if (m_read.joinable()) m_read.join();
    if (m_decode.joinable()) m_decode.join();
}

bool FFDecoder::OpenUrl(const char* url, int gpu)
{
    char    errbuf[64];
    int ret = avformat_open_input(&m_ifmt_ctx, url, 0, NULL);
    if (ret < 0) {
        printf("avformat_open_input '%s' (error '%s')\n", url, av_make_error_string(errbuf, sizeof(errbuf), ret));
        return false;
    }

    ret = avformat_find_stream_info(m_ifmt_ctx, NULL);
    if (ret < 0) {
        printf("avformat_find_stream_info (error '%s')\n", av_make_error_string(errbuf, sizeof(errbuf), ret));
        return false;
    }

    for (unsigned int i = 0; i < m_ifmt_ctx->nb_streams; i++) {
        av_dump_format(m_ifmt_ctx, i, url, 0);                                // dump information
        AVStream *st = m_ifmt_ctx->streams[i];
        switch(st->codecpar->codec_type) {
        case AVMEDIA_TYPE_AUDIO:
            break;
        case AVMEDIA_TYPE_VIDEO:
            m_video_index = i;
            GetCodec(AV_CODEC_ID_H264, gpu);
            break;
        default: break;
        }
    }
    if (m_avctx == NULL) {
        printf("No H.264 video stream in the input file\n");
        return false;
    }

    m_read = std::thread(ReadThread, this);

    return true;
}

bool FFDecoder::GetInfo(int *width, int *height)
{
    if (m_avctx == NULL) {
        return false;
    }

    *width = m_width;
    *height = m_height;
    return true;
}

bool FFDecoder::SetPacketData(uint8_t *data, int length)
{
    if( !data || length <= 0 )
        return false;

    AVPacket *pkt = av_packet_alloc();

#ifdef USE_CAMBRICON
    if( m_width < 0 || m_height < 0 )
    {    
        int ret = av_parser_parse2(m_parser, m_avctx, &pkt->data, &pkt->size,
                               data, length, AV_NOPTS_VALUE, AV_NOPTS_VALUE, 0);
        if (ret < 0) {
            printf("[FFDecoder] SetPacketData: Error while parsing\n");
            av_packet_free(&pkt);
            return false;
        }

        if( m_parser->width <= 0 || m_parser->height <= 0 )
        {
            printf("[FFDecoder] SetPacketData: width=%d, height=%d Error \n", m_parser->width, m_parser->height);
            av_packet_free(&pkt);
            return false;
        }

        m_width = m_parser->width;
        m_height = m_parser->height;

        if( CreateDecoder(m_codec_id, m_device) )
        {
            printf("[FFDecoder] SetPacketData: CreateDecoder Error \n");
            av_packet_free(&pkt);
            return false;
        }

        m_useCambricon = true;
    }
#endif

    av_new_packet(pkt, length);
    memcpy(pkt->data, data, length);
    std::lock_guard<std::mutex> lock(m_mtx);
    this->m_pkts.push_back(pkt);

    return true;
}

bool FFDecoder::GetRGBData(uint8_t *data, int width, int height)
{
    AVFrame *frame = NULL;
//    while (frame == NULL) 
    {
        std::lock_guard<std::mutex> lock(m_mtx_frames);
        if (!m_frames.empty()) {
            printf("FFDecoder::GetRGBData:framesize = %d \n", m_frames.size());
            frame = m_frames.front();
            m_frames.pop_front();
//            break;
        }
    }

    if (frame == NULL) {
        return false;
    }

    if (frame->format != AV_PIX_FMT_BGR24 || frame->width != width || frame->height != height) {
        m_swsContext = sws_getCachedContext(m_swsContext,
                                            frame->width, frame->height, (AVPixelFormat)frame->format,
                                            width, height, AV_PIX_FMT_BGR24,
                                            0, NULL, NULL, NULL);
        uint8_t *pixels[4] = { data };
        int pitch[4] = { width * 3 };
        sws_scale(m_swsContext, (const uint8_t *const *)frame->data, frame->linesize,
                  0, frame->height, pixels, pitch);
    } else {
        memcpy(data, frame->data[0], width * height * 3);
    }

    av_frame_free(&frame);
    return true;
}

bool FFDecoder::GetCodec(int codec_id, int gpu)
{
    int ret = 0;
    AVCodec *codec = NULL;
    const char *forced_codec_name = NULL;
    AVDictionary *opts = NULL;

    AVCodecContext *avctx = avcodec_alloc_context3(NULL);
    if (!avctx) {
        printf("avcodec_alloc_context3 error\n");
        return false;
    }

    codec_id = AV_CODEC_ID_H264;
    m_codec_id = codec_id;
    m_device = gpu;
    if (codec_id == AV_CODEC_ID_MJPEG) {
        forced_codec_name = "mjpeg_cuvid";
    } else if (codec_id == AV_CODEC_ID_H264) {
        forced_codec_name = "h264_cuvid";
    } else if (codec_id == AV_CODEC_ID_HEVC) {
        forced_codec_name = "hevc_cuvid";
    } else if (codec_id == AV_CODEC_ID_MPEG4) {
        forced_codec_name = "mpeg4_cuvid";
    }

    if (forced_codec_name) {
        codec = avcodec_find_decoder_by_name(forced_codec_name);
        if (codec) {
            char buf[32];
            snprintf(buf, 32, "%d", gpu);
            av_dict_set(&opts, "gpu", buf, 0);
            ret = avcodec_open2(avctx, codec, &opts);
            if (ret < 0) {
                char errbuf[64];
                printf("avcodec_open2 %s error '%s'\n", forced_codec_name, av_make_error_string(errbuf, sizeof(errbuf), ret));
                codec = NULL;
            }
        }
    }
    if (!codec) {
        codec = avcodec_find_decoder((AVCodecID)codec_id);
    }

    if (!codec) {
        printf("avcodec_find_decoder error\n");
        goto fail;
    }

    avctx->codec_id = codec->id;

    ret = avcodec_open2(avctx, codec, NULL);
    if (ret < 0) {
        char errbuf[64];
        printf("avcodec_open2 error '%s'\n", av_make_error_string(errbuf, sizeof(errbuf), ret));
        goto fail;
    }

    m_parser = av_parser_init(codec->id);
    if (!m_parser) {
        printf("[FFDecoder]:parser not found\n");
        goto fail;
    }
    m_parser->width = m_parser->height = -1;

    m_avctx = avctx;
    m_decode = std::thread(DecodeThread, this);

    goto out;

fail:
    avcodec_free_context(&avctx);
    av_dict_free(&opts);
    avctx = NULL;
    return false;

out:
    av_dict_free(&opts);
    return true;

}

void FFDecoder::ReadThread(FFDecoder *that)
{
    AVPacket *pkt = NULL;
    while (!that->m_stop) {
        if (pkt == NULL) {
            pkt = new AVPacket;
        }

        if (pkt == NULL) {
            printf("new AVPacket error, exit thread!!!");
            break;
        }

        int ret = av_read_frame(that->m_ifmt_ctx, pkt);
        if (ret < 0) {
            char errbuf[64];
            printf("av_read_frame error '%s', exit thread!!!\n", av_make_error_string(errbuf, sizeof(errbuf), ret));
            break;
        } else if (ret == AVERROR(EAGAIN)) {
            usleep(10 * 1000);
            continue;
        } else if (pkt->stream_index != that->m_video_index) {
            av_packet_unref(pkt);
        } else {
            that->SetPacketData(pkt->data, pkt->size);
            
            av_packet_unref(pkt);
            delete pkt;

//            std::lock_guard<std::mutex> lock(that->m_mtx);
//            that->m_pkts.push_back(pkt);
            pkt = NULL;
        }
    }

    if (pkt) {
        delete pkt;
        pkt = NULL;
    }
}

void FFDecoder::DecodeThread(FFDecoder *that)
{
    pthread_setname_np(pthread_self(), "video_decode");
    AVFrame *frame = av_frame_alloc();

#ifdef USE_CAMBRICON
    if (that->m_useCambricon) {
        cnrtSetCurrentDevice(that->cnrt_dev);
    }

    CN_VIDEO_PIC_PARAM_S  stPicParam;
    stPicParam.u64FrameIndex = 0;

#endif

    while (!that->m_stop) 
    {
        AVPacket *pkt = NULL;
        {
            std::lock_guard<std::mutex> lock(that->m_mtx);
            if (!that->m_pkts.empty()) 
            {
                printf("FFDecoder::DecodeThread:packetsize = %d \n", that->m_pkts.size());
                pkt = that->m_pkts.front();
                that->m_pkts.pop_front();
            }
        }

        if( !pkt )
        {
            usleep(20 * 1000);
            continue;
        }

#ifdef USE_CAMBRICON

        stPicParam.nBitstreamDataLen = pkt->size;
        stPicParam.pBitstreamData = (CN_U64)pkt->data;
        stPicParam.u64FrameIndex++;
        if (CN_SUCCESS  !=  CN_MPI_VDEC_Send(that->h_decoder, &stPicParam))
        {
            printf("CN_MPI_VDEC_Send failed!\n");
//                break;
        }

#else

        int got_frame = 0;
        int ret = avcodec_decode_video2(that->m_avctx, frame, &got_frame, pkt);
        if (ret < 0) 
        {
            printf("Error decoding video frame \n");
//            break;
        }
        else if( got_frame )
        {
            {
                std::lock_guard<std::mutex> lock(that->m_mtx_frames);
                that->m_width = frame->width;
                that->m_height = frame->height;
                that->m_frames.push_back(frame);
            }
            frame = av_frame_alloc();
            if (frame == NULL) {
                printf("av_frame_alloc error!!!");
                break;
            }
        }

#endif

        if ( pkt && pkt->data )
            av_packet_free(&pkt);

        usleep(10 * 1000);
    }

#ifdef USE_CAMBRICON
    if (that->m_useCambricon) {
        CN_MPI_VDEC_Destroy(that->h_decoder);  // 销毁通道
    }

    if (that->mlu_ptrs) {
        cnrtFree(that->mlu_ptrs);  // 释放解码图像输出内存
    }
#endif

}
