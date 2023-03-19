#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/blkdev.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
#include <linux/pci.h>
#include "mpt3sas_base.h"
#define MPT3_CONFIG_PAGE_DEFAULT_TIMEOUT 15
#define MPT3_CONFIG_COMMON_SGLFLAGS ((MPI2_SGE_FLAGS_SIMPLE_ELEMENT | \
	MPI2_SGE_FLAGS_LAST_ELEMENT | MPI2_SGE_FLAGS_END_OF_BUFFER \
	| MPI2_SGE_FLAGS_END_OF_LIST) << MPI2_SGE_FLAGS_SHIFT)
#define MPT3_CONFIG_COMMON_WRITE_SGLFLAGS ((MPI2_SGE_FLAGS_SIMPLE_ELEMENT | \
	MPI2_SGE_FLAGS_LAST_ELEMENT | MPI2_SGE_FLAGS_END_OF_BUFFER \
	| MPI2_SGE_FLAGS_END_OF_LIST | MPI2_SGE_FLAGS_HOST_TO_IOC) \
	<< MPI2_SGE_FLAGS_SHIFT)
struct config_request {
	u16			sz;
	void			*page;
	dma_addr_t		page_dma;
};
static int
_config_alloc_config_dma_memory(struct MPT3SAS_ADAPTER *ioc,
	struct config_request *mem)
{
	int r = 0;
	if (mem->sz > ioc->config_page_sz) {
		mem->page = dma_alloc_coherent(&ioc->pdev->dev, mem->sz,
		    &mem->page_dma, GFP_KERNEL);
		if (!mem->page) {
			ioc_err(ioc, "%s: dma_alloc_coherent failed asking for (%d) bytes!!\n",
				__func__, mem->sz);
			r = -ENOMEM;
		}
	} else { 
		mem->page = ioc->config_page;
		mem->page_dma = ioc->config_page_dma;
	}
	ioc->config_vaddr = mem->page;
	return r;
}
static void
_config_free_config_dma_memory(struct MPT3SAS_ADAPTER *ioc,
	struct config_request *mem)
{
	if (mem->sz > ioc->config_page_sz)
		dma_free_coherent(&ioc->pdev->dev, mem->sz, mem->page,
		    mem->page_dma);
}
u8
mpt3sas_config_done(struct MPT3SAS_ADAPTER *ioc, u16 smid, u8 msix_index,
	u32 reply)
{
	MPI2DefaultReply_t *mpi_reply;
	if (ioc->config_cmds.status == MPT3_CMD_NOT_USED)
		return 1;
	if (ioc->config_cmds.smid != smid)
		return 1;
	ioc->config_cmds.status |= MPT3_CMD_COMPLETE;
	mpi_reply =  mpt3sas_base_get_reply_virt_addr(ioc, reply);
	if (mpi_reply) {
		ioc->config_cmds.status |= MPT3_CMD_REPLY_VALID;
		memcpy(ioc->config_cmds.reply, mpi_reply,
		    mpi_reply->MsgLength*4);
	}
	ioc->config_cmds.status &= ~MPT3_CMD_PENDING;
			ioc->config_cmds.smid = USHRT_MAX;
	complete(&ioc->config_cmds.done);
	return 1;
}
static int
_config_request(struct MPT3SAS_ADAPTER *ioc, Mpi2ConfigRequest_t
	*mpi_request, Mpi2ConfigReply_t *mpi_reply, int timeout,
	void *config_page, u16 config_page_sz)
{
	u16 smid;
	Mpi2ConfigRequest_t *config_request;
	int r;
	u8 issue_host_reset = 0; 	struct config_request mem;
	u32 ioc_status = UINT_MAX;
	mutex_lock(&ioc->config_cmds.mutex);
	if (ioc->config_cmds.status != MPT3_CMD_NOT_USED) {
		ioc_err(ioc, "%s: config_cmd in use\n", __func__);
		mutex_unlock(&ioc->config_cmds.mutex);
		return -EAGAIN;
	}
		memset(&mem, 0, sizeof(struct config_request));
	mpi_request->VF_ID = 0;
	mpi_request->VP_ID = 0;
	if (config_page) {
		mpi_request->Header.PageVersion = mpi_reply->Header.PageVersion;
		mpi_request->Header.PageNumber = mpi_reply->Header.PageNumber;
		mpi_request->Header.PageType = mpi_reply->Header.PageType;
		mpi_request->Header.PageLength = mpi_reply->Header.PageLength;
		mpi_request->ExtPageLength = mpi_reply->ExtPageLength;
		mpi_request->ExtPageType = mpi_reply->ExtPageType;
		if (mpi_request->Header.PageLength)
			mem.sz = mpi_request->Header.PageLength * 4;
		else
			mem.sz = le16_to_cpu(mpi_reply->ExtPageLength) * 4;
		r = _config_alloc_config_dma_memory(ioc, &mem);
		if (r != 0)
			goto out;
		if (mpi_request->Action ==
		    MPI2_CONFIG_ACTION_PAGE_WRITE_CURRENT ||
		    mpi_request->Action ==
		    MPI2_CONFIG_ACTION_PAGE_WRITE_NVRAM) {
			ioc->base_add_sg_single(&mpi_request->PageBufferSGE,
			    MPT3_CONFIG_COMMON_WRITE_SGLFLAGS | mem.sz,
			    mem.page_dma);
			memcpy(mem.page, config_page, min_t(u16, mem.sz,
			    config_page_sz));
		} else {
			memset(config_page, 0, config_page_sz);
			ioc->base_add_sg_single(&mpi_request->PageBufferSGE,
			    MPT3_CONFIG_COMMON_SGLFLAGS | mem.sz, mem.page_dma);
			memset(mem.page, 0, min_t(u16, mem.sz, config_page_sz));
		}
	}
	r = mpt3sas_wait_for_ioc(ioc, MPT3_CONFIG_PAGE_DEFAULT_TIMEOUT);
	if (r) {
		if (r == -ETIME)
			issue_host_reset = 1;
		goto free_mem;
	}
	smid = mpt3sas_base_get_smid(ioc, ioc->config_cb_idx); 
	if (!smid) {
		ioc_err(ioc, "%s: failed obtaining a smid\n", __func__);
		ioc->config_cmds.status = MPT3_CMD_NOT_USED;
		r = -EAGAIN;
		goto free_mem;
	}
	r = 0;
	memset(ioc->config_cmds.reply, 0, sizeof(Mpi2ConfigReply_t));
	ioc->config_cmds.status = MPT3_CMD_PENDING;
	config_request = mpt3sas_base_get_msg_frame(ioc, smid); 
	ioc->config_cmds.smid = smid;
	memcpy(config_request, mpi_request, sizeof(Mpi2ConfigRequest_t));
			init_completion(&ioc->config_cmds.done);
	ioc->put_smid_default(ioc, smid);
	wait_for_completion_timeout(&ioc->config_cmds.done, timeout*HZ);
	if (!(ioc->config_cmds.status & MPT3_CMD_COMPLETE)) {
		pr_alert("%s 未能正常完成第一步 config page, 几乎不太可能\n", __func__);
																													}
	if (ioc->config_cmds.status & MPT3_CMD_REPLY_VALID) {
		memcpy(mpi_reply, ioc->config_cmds.reply,
		    sizeof(Mpi2ConfigReply_t));
		if ((mpi_request->Header.PageType & 0xF) !=
		    (mpi_reply->Header.PageType & 0xF)) {
																		panic("%s: %s: Firmware BUG: mpi_reply mismatch: Requested PageType(0x%02x) Reply PageType(0x%02x)\n",
			      ioc->name, __func__,
			      mpi_request->Header.PageType & 0xF,
			      mpi_reply->Header.PageType & 0xF);
		}
		if (((mpi_request->Header.PageType & 0xF) ==
		    MPI2_CONFIG_PAGETYPE_EXTENDED) &&
		    mpi_request->ExtPageType != mpi_reply->ExtPageType) {
																		panic("%s: %s: Firmware BUG: mpi_reply mismatch: Requested ExtPageType(0x%02x) Reply ExtPageType(0x%02x)\n",
			      ioc->name, __func__,
			      mpi_request->ExtPageType,
			      mpi_reply->ExtPageType);
		}
		ioc_status = le16_to_cpu(mpi_reply->IOCStatus) & MPI2_IOCSTATUS_MASK;
	}
	if ((ioc_status == MPI2_IOCSTATUS_SUCCESS) &&
	    config_page && mpi_request->Action ==
	    MPI2_CONFIG_ACTION_PAGE_READ_CURRENT) {
		u8 *p = (u8 *)mem.page;
		if (p) {
			if ((mpi_request->Header.PageType & 0xF) !=
			    (p[3] & 0xF)) {
																																panic("%s: %s: Firmware BUG: config page mismatch: Requested PageType(0x%02x) Reply PageType(0x%02x)\n",
				      ioc->name, __func__,
				      mpi_request->Header.PageType & 0xF,
				      p[3] & 0xF);
			}
			if (((mpi_request->Header.PageType & 0xF) ==
			    MPI2_CONFIG_PAGETYPE_EXTENDED) &&
			    (mpi_request->ExtPageType != p[6])) {
																																panic("%s: %s: Firmware BUG: config page mismatch: Requested ExtPageType(0x%02x) Reply ExtPageType(0x%02x)\n",
				      ioc->name, __func__,
				      mpi_request->ExtPageType, p[6]);
			}
		}
		memcpy(config_page, mem.page, min_t(u16, mem.sz,
		    config_page_sz));
	}
free_mem:
	if (config_page)
		_config_free_config_dma_memory(ioc, &mem);
out:
	ioc->config_cmds.status = MPT3_CMD_NOT_USED;
	mutex_unlock(&ioc->config_cmds.mutex);
											return r;
}
int
mpt3sas_config_get_manufacturing_pg0(struct MPT3SAS_ADAPTER *ioc,
	Mpi2ConfigReply_t *mpi_reply, Mpi2ManufacturingPage0_t *config_page)
{
	Mpi2ConfigRequest_t mpi_request;
	int r;
	memset(&mpi_request, 0, sizeof(Mpi2ConfigRequest_t)); 
	mpi_request.Function = MPI2_FUNCTION_CONFIG; 
	mpi_request.Action = MPI2_CONFIG_ACTION_PAGE_HEADER;
	mpi_request.Header.PageType = MPI2_CONFIG_PAGETYPE_MANUFACTURING;
	mpi_request.Header.PageNumber = 0;
	mpi_request.Header.PageVersion = MPI2_MANUFACTURING0_PAGEVERSION;
	ioc->build_zero_len_sge_mpi(ioc, &mpi_request.PageBufferSGE); 
	r = _config_request(ioc, &mpi_request, mpi_reply,
	    MPT3_CONFIG_PAGE_DEFAULT_TIMEOUT, NULL, 0);
	if (r)
		goto out;
	mpi_request.Action = MPI2_CONFIG_ACTION_PAGE_READ_CURRENT;
	r = _config_request(ioc, &mpi_request, mpi_reply,
	    MPT3_CONFIG_PAGE_DEFAULT_TIMEOUT, config_page,
	    sizeof(*config_page));
out:
	return r;
}
int
mpt3sas_config_get_manufacturing_pg11(struct MPT3SAS_ADAPTER *ioc,
	Mpi2ConfigReply_t *mpi_reply,
	struct Mpi2ManufacturingPage11_t *config_page)
{
	Mpi2ConfigRequest_t mpi_request;
	int r;
	memset(&mpi_request, 0, sizeof(Mpi2ConfigRequest_t));
	mpi_request.Function = MPI2_FUNCTION_CONFIG;
	mpi_request.Action = MPI2_CONFIG_ACTION_PAGE_HEADER;
	mpi_request.Header.PageType = MPI2_CONFIG_PAGETYPE_MANUFACTURING;
	mpi_request.Header.PageNumber = 11;
	mpi_request.Header.PageVersion = MPI2_MANUFACTURING0_PAGEVERSION;
	ioc->build_zero_len_sge_mpi(ioc, &mpi_request.PageBufferSGE);
	r = _config_request(ioc, &mpi_request, mpi_reply,
	    MPT3_CONFIG_PAGE_DEFAULT_TIMEOUT, NULL, 0);
	if (r)
		goto out;
	mpi_request.Action = MPI2_CONFIG_ACTION_PAGE_READ_CURRENT;
	r = _config_request(ioc, &mpi_request, mpi_reply,
	    MPT3_CONFIG_PAGE_DEFAULT_TIMEOUT, config_page,
	    sizeof(*config_page));
 out:
	return r;
}
int
mpt3sas_config_set_manufacturing_pg11(struct MPT3SAS_ADAPTER *ioc,
	Mpi2ConfigReply_t *mpi_reply,
	struct Mpi2ManufacturingPage11_t *config_page)
{
	Mpi2ConfigRequest_t mpi_request;
	int r;
	memset(&mpi_request, 0, sizeof(Mpi2ConfigRequest_t));
	mpi_request.Function = MPI2_FUNCTION_CONFIG;
	mpi_request.Action = MPI2_CONFIG_ACTION_PAGE_HEADER;
	mpi_request.Header.PageType = MPI2_CONFIG_PAGETYPE_MANUFACTURING;
	mpi_request.Header.PageNumber = 11;
	mpi_request.Header.PageVersion = MPI2_MANUFACTURING0_PAGEVERSION;
	ioc->build_zero_len_sge_mpi(ioc, &mpi_request.PageBufferSGE);
	r = _config_request(ioc, &mpi_request, mpi_reply,
	    MPT3_CONFIG_PAGE_DEFAULT_TIMEOUT, NULL, 0);
	if (r)
		goto out;
	mpi_request.Action = MPI2_CONFIG_ACTION_PAGE_WRITE_CURRENT;
	r = _config_request(ioc, &mpi_request, mpi_reply,
	    MPT3_CONFIG_PAGE_DEFAULT_TIMEOUT, config_page,
	    sizeof(*config_page));
 out:
	return r;
}
int
mpt3sas_config_get_iounit_pg0(struct MPT3SAS_ADAPTER *ioc,
	Mpi2ConfigReply_t *mpi_reply, Mpi2IOUnitPage0_t *config_page)
{
	Mpi2ConfigRequest_t mpi_request;
	int r;
	memset(&mpi_request, 0, sizeof(Mpi2ConfigRequest_t));
	mpi_request.Function = MPI2_FUNCTION_CONFIG;
	mpi_request.Action = MPI2_CONFIG_ACTION_PAGE_HEADER;
	mpi_request.Header.PageType = MPI2_CONFIG_PAGETYPE_IO_UNIT;
	mpi_request.Header.PageNumber = 0;
	mpi_request.Header.PageVersion = MPI2_IOUNITPAGE0_PAGEVERSION;
	ioc->build_zero_len_sge_mpi(ioc, &mpi_request.PageBufferSGE);
	r = _config_request(ioc, &mpi_request, mpi_reply,
	    MPT3_CONFIG_PAGE_DEFAULT_TIMEOUT, NULL, 0);
	if (r)
		goto out;
	mpi_request.Action = MPI2_CONFIG_ACTION_PAGE_READ_CURRENT;
	r = _config_request(ioc, &mpi_request, mpi_reply,
	    MPT3_CONFIG_PAGE_DEFAULT_TIMEOUT, config_page,
	    sizeof(*config_page));
out:
	return r;
}
int
mpt3sas_config_get_iounit_pg1(struct MPT3SAS_ADAPTER *ioc,
	Mpi2ConfigReply_t *mpi_reply, Mpi2IOUnitPage1_t *config_page)
{
	Mpi2ConfigRequest_t mpi_request;
	int r;
	memset(&mpi_request, 0, sizeof(Mpi2ConfigRequest_t));
	mpi_request.Function = MPI2_FUNCTION_CONFIG;
	mpi_request.Action = MPI2_CONFIG_ACTION_PAGE_HEADER;
	mpi_request.Header.PageType = MPI2_CONFIG_PAGETYPE_IO_UNIT;
	mpi_request.Header.PageNumber = 1;
	mpi_request.Header.PageVersion = MPI2_IOUNITPAGE1_PAGEVERSION;
	ioc->build_zero_len_sge_mpi(ioc, &mpi_request.PageBufferSGE);
	r = _config_request(ioc, &mpi_request, mpi_reply,
	    MPT3_CONFIG_PAGE_DEFAULT_TIMEOUT, NULL, 0);
	if (r)
		goto out;
	mpi_request.Action = MPI2_CONFIG_ACTION_PAGE_READ_CURRENT;
	r = _config_request(ioc, &mpi_request, mpi_reply,
	    MPT3_CONFIG_PAGE_DEFAULT_TIMEOUT, config_page,
	    sizeof(*config_page));
 out:
	return r;
}
int
mpt3sas_config_set_iounit_pg1(struct MPT3SAS_ADAPTER *ioc,
	Mpi2ConfigReply_t *mpi_reply, Mpi2IOUnitPage1_t *config_page)
{
	Mpi2ConfigRequest_t mpi_request;
	int r;
	memset(&mpi_request, 0, sizeof(Mpi2ConfigRequest_t));
	mpi_request.Function = MPI2_FUNCTION_CONFIG;
	mpi_request.Action = MPI2_CONFIG_ACTION_PAGE_HEADER;
	mpi_request.Header.PageType = MPI2_CONFIG_PAGETYPE_IO_UNIT;
	mpi_request.Header.PageNumber = 1;
	mpi_request.Header.PageVersion = MPI2_IOUNITPAGE1_PAGEVERSION;
	ioc->build_zero_len_sge_mpi(ioc, &mpi_request.PageBufferSGE);
	r = _config_request(ioc, &mpi_request, mpi_reply,
	    MPT3_CONFIG_PAGE_DEFAULT_TIMEOUT, NULL, 0);
	if (r)
		goto out;
	mpi_request.Action = MPI2_CONFIG_ACTION_PAGE_WRITE_CURRENT;
	r = _config_request(ioc, &mpi_request, mpi_reply,
	    MPT3_CONFIG_PAGE_DEFAULT_TIMEOUT, config_page,
	    sizeof(*config_page));
 out:
	return r;
}
int
mpt3sas_config_get_iounit_pg8(struct MPT3SAS_ADAPTER *ioc,
	Mpi2ConfigReply_t *mpi_reply, Mpi2IOUnitPage8_t *config_page)
{
	Mpi2ConfigRequest_t mpi_request;
	int r;
	memset(&mpi_request, 0, sizeof(Mpi2ConfigRequest_t));
	mpi_request.Function = MPI2_FUNCTION_CONFIG;
	mpi_request.Action = MPI2_CONFIG_ACTION_PAGE_HEADER;
	mpi_request.Header.PageType = MPI2_CONFIG_PAGETYPE_IO_UNIT;
	mpi_request.Header.PageNumber = 8;
	mpi_request.Header.PageVersion = MPI2_IOUNITPAGE8_PAGEVERSION;
	ioc->build_zero_len_sge_mpi(ioc, &mpi_request.PageBufferSGE);
	r = _config_request(ioc, &mpi_request, mpi_reply,
	    MPT3_CONFIG_PAGE_DEFAULT_TIMEOUT, NULL, 0);
	if (r)
		goto out;
	mpi_request.Action = MPI2_CONFIG_ACTION_PAGE_READ_CURRENT;
	r = _config_request(ioc, &mpi_request, mpi_reply,
	    MPT3_CONFIG_PAGE_DEFAULT_TIMEOUT, config_page,
	    sizeof(*config_page));
out:
	return r;
}
int
mpt3sas_config_get_sas_device_pg0(struct MPT3SAS_ADAPTER *ioc,
	Mpi2ConfigReply_t *mpi_reply, Mpi2SasDevicePage0_t *config_page,
	u32 form, u32 handle)
{
	Mpi2ConfigRequest_t mpi_request;
	int r;
	memset(&mpi_request, 0, sizeof(Mpi2ConfigRequest_t));
	mpi_request.Function = MPI2_FUNCTION_CONFIG;
	mpi_request.Action = MPI2_CONFIG_ACTION_PAGE_HEADER;
	mpi_request.Header.PageType = MPI2_CONFIG_PAGETYPE_EXTENDED;
	mpi_request.ExtPageType = MPI2_CONFIG_EXTPAGETYPE_SAS_DEVICE;
	mpi_request.Header.PageVersion = MPI2_SASDEVICE0_PAGEVERSION;
	mpi_request.Header.PageNumber = 0;
	ioc->build_zero_len_sge_mpi(ioc, &mpi_request.PageBufferSGE);
	r = _config_request(ioc, &mpi_request, mpi_reply,
	    MPT3_CONFIG_PAGE_DEFAULT_TIMEOUT, NULL, 0);
	if (r)
		goto out;
	mpi_request.PageAddress = cpu_to_le32(form | handle);
	mpi_request.Action = MPI2_CONFIG_ACTION_PAGE_READ_CURRENT;
	r = _config_request(ioc, &mpi_request, mpi_reply,
	    MPT3_CONFIG_PAGE_DEFAULT_TIMEOUT, config_page,
	    sizeof(*config_page));
out:
	return r;
}
int
mpt3sas_config_get_number_hba_phys(struct MPT3SAS_ADAPTER *ioc, u8 *num_phys)
{
	Mpi2ConfigRequest_t mpi_request;
	int r;
	u16 ioc_status;
	Mpi2ConfigReply_t mpi_reply;
	Mpi2SasIOUnitPage0_t config_page;
	*num_phys = 0;
	memset(&mpi_request, 0, sizeof(Mpi2ConfigRequest_t));
	mpi_request.Function = MPI2_FUNCTION_CONFIG;
	mpi_request.Action = MPI2_CONFIG_ACTION_PAGE_HEADER;
	mpi_request.Header.PageType = MPI2_CONFIG_PAGETYPE_EXTENDED;
	mpi_request.ExtPageType = MPI2_CONFIG_EXTPAGETYPE_SAS_IO_UNIT;
	mpi_request.Header.PageNumber = 0;
	mpi_request.Header.PageVersion = MPI2_SASIOUNITPAGE0_PAGEVERSION;
	ioc->build_zero_len_sge_mpi(ioc, &mpi_request.PageBufferSGE);
	r = _config_request(ioc, &mpi_request, &mpi_reply,
	    MPT3_CONFIG_PAGE_DEFAULT_TIMEOUT, NULL, 0);
	if (r)
		goto out;
	mpi_request.Action = MPI2_CONFIG_ACTION_PAGE_READ_CURRENT;
	r = _config_request(ioc, &mpi_request, &mpi_reply,
	    MPT3_CONFIG_PAGE_DEFAULT_TIMEOUT, &config_page,
	    sizeof(Mpi2SasIOUnitPage0_t));
	if (!r) {
		ioc_status = le16_to_cpu(mpi_reply.IOCStatus) &
		    MPI2_IOCSTATUS_MASK;
		if (ioc_status == MPI2_IOCSTATUS_SUCCESS)
			*num_phys = config_page.NumPhys;
	}
 out:
	return r;
}
int
mpt3sas_config_get_sas_iounit_pg0(struct MPT3SAS_ADAPTER *ioc,
	Mpi2ConfigReply_t *mpi_reply, Mpi2SasIOUnitPage0_t *config_page,
	u16 sz)
{
	Mpi2ConfigRequest_t mpi_request;
	int r;
	memset(&mpi_request, 0, sizeof(Mpi2ConfigRequest_t));
	mpi_request.Function = MPI2_FUNCTION_CONFIG;
	mpi_request.Action = MPI2_CONFIG_ACTION_PAGE_HEADER;
	mpi_request.Header.PageType = MPI2_CONFIG_PAGETYPE_EXTENDED;
	mpi_request.ExtPageType = MPI2_CONFIG_EXTPAGETYPE_SAS_IO_UNIT;
	mpi_request.Header.PageNumber = 0;
	mpi_request.Header.PageVersion = MPI2_SASIOUNITPAGE0_PAGEVERSION;
	ioc->build_zero_len_sge_mpi(ioc, &mpi_request.PageBufferSGE);
	r = _config_request(ioc, &mpi_request, mpi_reply,
	    MPT3_CONFIG_PAGE_DEFAULT_TIMEOUT, NULL, 0);
	if (r)
		goto out;
	mpi_request.Action = MPI2_CONFIG_ACTION_PAGE_READ_CURRENT;
	r = _config_request(ioc, &mpi_request, mpi_reply,
	    MPT3_CONFIG_PAGE_DEFAULT_TIMEOUT, config_page, sz);
 out:
	return r;
}
int
mpt3sas_config_get_sas_iounit_pg1(struct MPT3SAS_ADAPTER *ioc,
	Mpi2ConfigReply_t *mpi_reply, Mpi2SasIOUnitPage1_t *config_page,
	u16 sz)
{
	Mpi2ConfigRequest_t mpi_request;
	int r;
	memset(&mpi_request, 0, sizeof(Mpi2ConfigRequest_t));
	mpi_request.Function = MPI2_FUNCTION_CONFIG;
	mpi_request.Action = MPI2_CONFIG_ACTION_PAGE_HEADER;
	mpi_request.Header.PageType = MPI2_CONFIG_PAGETYPE_EXTENDED;
	mpi_request.ExtPageType = MPI2_CONFIG_EXTPAGETYPE_SAS_IO_UNIT;
	mpi_request.Header.PageNumber = 1;
	mpi_request.Header.PageVersion = MPI2_SASIOUNITPAGE1_PAGEVERSION;
	ioc->build_zero_len_sge_mpi(ioc, &mpi_request.PageBufferSGE);
	r = _config_request(ioc, &mpi_request, mpi_reply,
	    MPT3_CONFIG_PAGE_DEFAULT_TIMEOUT, NULL, 0);
	if (r)
		goto out;
	mpi_request.Action = MPI2_CONFIG_ACTION_PAGE_READ_CURRENT;
	r = _config_request(ioc, &mpi_request, mpi_reply,
	    MPT3_CONFIG_PAGE_DEFAULT_TIMEOUT, config_page, sz);
 out:
	return r;
}
int
mpt3sas_config_get_phy_pg0(struct MPT3SAS_ADAPTER *ioc, Mpi2ConfigReply_t
	*mpi_reply, Mpi2SasPhyPage0_t *config_page, u32 phy_number)
{
	Mpi2ConfigRequest_t mpi_request;
	int r;
	memset(&mpi_request, 0, sizeof(Mpi2ConfigRequest_t));
	mpi_request.Function = MPI2_FUNCTION_CONFIG;
	mpi_request.Action = MPI2_CONFIG_ACTION_PAGE_HEADER;
	mpi_request.Header.PageType = MPI2_CONFIG_PAGETYPE_EXTENDED;
	mpi_request.ExtPageType = MPI2_CONFIG_EXTPAGETYPE_SAS_PHY;
	mpi_request.Header.PageNumber = 0;
	mpi_request.Header.PageVersion = MPI2_SASPHY0_PAGEVERSION;
	ioc->build_zero_len_sge_mpi(ioc, &mpi_request.PageBufferSGE);
	r = _config_request(ioc, &mpi_request, mpi_reply,
	    MPT3_CONFIG_PAGE_DEFAULT_TIMEOUT, NULL, 0);
	if (r)
		goto out;
	mpi_request.PageAddress =
	    cpu_to_le32(MPI2_SAS_PHY_PGAD_FORM_PHY_NUMBER | phy_number);
	mpi_request.Action = MPI2_CONFIG_ACTION_PAGE_READ_CURRENT;
	r = _config_request(ioc, &mpi_request, mpi_reply,
	    MPT3_CONFIG_PAGE_DEFAULT_TIMEOUT, config_page,
	    sizeof(*config_page));
 out:
	return r;
}
