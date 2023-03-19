#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/pci.h>
#include <linux/kdev_t.h>
#include <linux/blkdev.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/dma-mapping.h>
#include <linux/io.h>
#include <linux/time.h>
#include <linux/ktime.h>
#include <linux/kthread.h>
#include <asm/page.h>        
#include <linux/aer.h>
#include "mpt3sas_base.h"
static MPT_CALLBACK	mpt_callbacks[MPT_MAX_CALLBACKS];
#define FAULT_POLLING_INTERVAL 1000 
#define MAX_HBA_QUEUE_DEPTH	30000
#define MAX_CHAIN_DEPTH		100000
static int max_queue_depth = -1;
module_param(max_queue_depth, int, 0444);
MODULE_PARM_DESC(max_queue_depth, " max controller queue depth ");
static int smp_affinity_enable = 1;
module_param(smp_affinity_enable, int, 0444);
MODULE_PARM_DESC(smp_affinity_enable, "SMP affinity feature enable/disable Default: enable(1)");
static int
_base_wait_on_iocstate(struct MPT3SAS_ADAPTER *ioc,
		u32 ioc_state, int timeout);
static int
_base_get_ioc_facts(struct MPT3SAS_ADAPTER *ioc);
u8
mpt3sas_base_check_cmd_timeout(struct MPT3SAS_ADAPTER *ioc,
		u8 status, void *mpi_request, int sz)
{
	u8 issue_reset = 0;
	if (!(status & MPT3_CMD_RESET))
		issue_reset = 1;
	ioc_err(ioc, "Command %s\n",
		issue_reset == 0 ? "terminated due to Host Reset" : "Timeout");
	return issue_reset;
}
static inline u32
_base_readl(const volatile void __iomem *addr)
{
	return readl(addr);
}
void
mpt3sas_halt_firmware(struct MPT3SAS_ADAPTER *ioc)
{
	u32 doorbell;
	dump_stack();
	doorbell = ioc->base_readl(&ioc->chip->Doorbell);
	if ((doorbell & MPI2_IOC_STATE_MASK) == MPI2_IOC_STATE_FAULT) {
			} else if ((doorbell & MPI2_IOC_STATE_MASK) ==
	    MPI2_IOC_STATE_COREDUMP) {
			} else {
		writel(0xC0FFEE00, &ioc->chip->Doorbell);
		ioc_err(ioc, "Firmware is halted due to command timeout\n");
	}
						panic("panic in %s\n", __func__);
}
u8
mpt3sas_base_done(struct MPT3SAS_ADAPTER *ioc, u16 smid, u8 msix_index,
	u32 reply)
{
	MPI2DefaultReply_t *mpi_reply;
	pr_err("%s\n", __func__);
	mpi_reply = mpt3sas_base_get_reply_virt_addr(ioc, reply);
	if (mpi_reply && mpi_reply->Function == MPI2_FUNCTION_EVENT_ACK)
		return mpt3sas_check_for_pending_internal_cmds(ioc, smid);
	if (ioc->base_cmds.status == MPT3_CMD_NOT_USED)
		return 1;
	ioc->base_cmds.status |= MPT3_CMD_COMPLETE;
	if (mpi_reply) {
		ioc->base_cmds.status |= MPT3_CMD_REPLY_VALID;
		memcpy(ioc->base_cmds.reply, mpi_reply, mpi_reply->MsgLength*4);
	}
	ioc->base_cmds.status &= ~MPT3_CMD_PENDING;
	complete(&ioc->base_cmds.done);
	return 1;
}
static u8
_base_async_event(struct MPT3SAS_ADAPTER *ioc, u8 msix_index, u32 reply)
{
	Mpi2EventNotificationReply_t *mpi_reply;
				pr_err("%s\n", __func__);
	mpi_reply = mpt3sas_base_get_reply_virt_addr(ioc, reply);
	if (!mpi_reply)
		return 1;
	if (mpi_reply->Function != MPI2_FUNCTION_EVENT_NOTIFICATION)
		return 1;
	mpt3sas_scsih_event_callback(ioc, msix_index, reply);
	return 1;
}
static struct scsiio_tracker *
_get_st_from_smid(struct MPT3SAS_ADAPTER *ioc, u16 smid)
{
	struct scsi_cmnd *cmd;
	if (WARN_ON(!smid) ||
	    WARN_ON(smid >= ioc->hi_priority_smid))
		return NULL;
	cmd = mpt3sas_scsih_scsi_lookup_get(ioc, smid);
	if (cmd)
		return scsi_cmd_priv(cmd);
	return NULL;
}
static u8
_base_get_cb_idx(struct MPT3SAS_ADAPTER *ioc, u16 smid)
{
	int i;
		u8 cb_idx = 0xFF;
	if (smid < ioc->hi_priority_smid) {
		struct scsiio_tracker *st; 
					st = _get_st_from_smid(ioc, smid);
			if (st)
				cb_idx = st->cb_idx;
					} else if (smid < ioc->internal_smid) {
		i = smid - ioc->hi_priority_smid;
		cb_idx = ioc->hpr_lookup[i].cb_idx;
	} else if (smid <= ioc->hba_queue_depth) {
		i = smid - ioc->internal_smid;
		cb_idx = ioc->internal_lookup[i].cb_idx;
	}
	return cb_idx;
}
void
mpt3sas_base_mask_interrupts(struct MPT3SAS_ADAPTER *ioc)
{
	u32 him_register;
	ioc->mask_interrupts = 1;
	him_register = ioc->base_readl(&ioc->chip->HostInterruptMask); 
	pr_err("%s befor him_register=0x%x\n", __func__, him_register);
	him_register |= MPI2_HIM_DIM + MPI2_HIM_RIM + MPI2_HIM_RESET_IRQ_MASK;
	pr_err("%s after him_register=0x%x\n", __func__, him_register);
	writel(him_register, &ioc->chip->HostInterruptMask);
	ioc->base_readl(&ioc->chip->HostInterruptMask); 
}
void
mpt3sas_base_unmask_interrupts(struct MPT3SAS_ADAPTER *ioc)
{
	u32 him_register;
	him_register = ioc->base_readl(&ioc->chip->HostInterruptMask);
	him_register &= ~MPI2_HIM_RIM;
	writel(him_register, &ioc->chip->HostInterruptMask);
	ioc->mask_interrupts = 0;
}
union reply_descriptor {
	u64 word;
	struct {
		u32 low;
		u32 high;
	} u;
};
static int
_base_process_reply_queue(struct adapter_reply_queue *reply_q)
{
	union reply_descriptor rd;
	u64 completed_cmds;
	u8 request_descript_type;
	u16 smid;
	u8 cb_idx;
	u32 reply;
	u8 msix_index = reply_q->msix_index;
	struct MPT3SAS_ADAPTER *ioc = reply_q->ioc;
	Mpi2ReplyDescriptorsUnion_t *rpf;
	u8 rc;
	completed_cmds = 0;
	if (!atomic_add_unless(&reply_q->busy, 1, 1))
		return completed_cmds;
	rpf = &reply_q->reply_post_free[reply_q->reply_post_host_index];
	request_descript_type = rpf->Default.ReplyFlags
	     & MPI2_RPY_DESCRIPT_FLAGS_TYPE_MASK;
	if (request_descript_type == MPI2_RPY_DESCRIPT_FLAGS_UNUSED) {
		atomic_dec(&reply_q->busy);
		return completed_cmds;
	}
	cb_idx = 0xFF;
	do {
		rd.word = le64_to_cpu(rpf->Words);
		if (rd.u.low == UINT_MAX || rd.u.high == UINT_MAX)
			goto out;
		reply = 0;
		smid = le16_to_cpu(rpf->Default.DescriptorTypeDependent1);
		if (request_descript_type ==
		    MPI25_RPY_DESCRIPT_FLAGS_FAST_PATH_SCSI_IO_SUCCESS ||
		    request_descript_type ==
		    MPI2_RPY_DESCRIPT_FLAGS_SCSI_IO_SUCCESS ||
		    request_descript_type ==
		    MPI26_RPY_DESCRIPT_FLAGS_PCIE_ENCAPSULATED_SUCCESS) { 
			cb_idx = _base_get_cb_idx(ioc, smid);
			if ((likely(cb_idx < MPT_MAX_CALLBACKS)) &&
			    (likely(mpt_callbacks[cb_idx] != NULL))) {
				rc = mpt_callbacks[cb_idx](ioc, smid, msix_index, 0); 
				if (rc) 
					mpt3sas_base_free_smid(ioc, smid);
			}
		} else if (request_descript_type ==
		    MPI2_RPY_DESCRIPT_FLAGS_ADDRESS_REPLY) { 
			reply = le32_to_cpu(
			    rpf->AddressReply.ReplyFrameAddress); 
			if (reply > ioc->reply_dma_max_address ||
			    reply < ioc->reply_dma_min_address)
				reply = 0; 
			if (smid) { 
				cb_idx = _base_get_cb_idx(ioc, smid);
				if ((likely(cb_idx < MPT_MAX_CALLBACKS)) &&
				    (likely(mpt_callbacks[cb_idx] != NULL))) {
					rc = mpt_callbacks[cb_idx](ioc, smid, msix_index, reply);
																				if (rc)
						mpt3sas_base_free_smid(ioc, smid);
				}
			} else {
				_base_async_event(ioc, msix_index, reply); 
			}
			if (reply) { 
				ioc->reply_free_host_index =
				    (ioc->reply_free_host_index ==
				    (ioc->reply_free_queue_depth - 1)) ?
				    0 : ioc->reply_free_host_index + 1; 
				ioc->reply_free[ioc->reply_free_host_index] =
				    cpu_to_le32(reply);
																				writel(ioc->reply_free_host_index,
				    &ioc->chip->ReplyFreeHostIndex); 
			}
		}
		rpf->Words = cpu_to_le64(ULLONG_MAX); 
		reply_q->reply_post_host_index =
		    (reply_q->reply_post_host_index ==
		    (ioc->reply_post_queue_depth - 1)) ? 0 :
		    reply_q->reply_post_host_index + 1; 
		request_descript_type =
		    reply_q->reply_post_free[reply_q->reply_post_host_index].
		    Default.ReplyFlags & MPI2_RPY_DESCRIPT_FLAGS_TYPE_MASK;
		completed_cmds++;
		if (completed_cmds >= ioc->thresh_hold) {
			if (ioc->combined_reply_queue) {
				writel(reply_q->reply_post_host_index |
						((msix_index  & 7) <<
						 MPI2_RPHI_MSIX_INDEX_SHIFT),
				    ioc->replyPostRegisterIndex[msix_index/8]);
			} else {
				writel(reply_q->reply_post_host_index |
						(msix_index <<
						 MPI2_RPHI_MSIX_INDEX_SHIFT),
						&ioc->chip->ReplyPostHostIndex);
			}
																		atomic_dec(&reply_q->busy);
			return completed_cmds;
		}
		if (request_descript_type == MPI2_RPY_DESCRIPT_FLAGS_UNUSED)
			goto out;
		if (!reply_q->reply_post_host_index)
			rpf = reply_q->reply_post_free;
		else
			rpf++;
	} while (1);
out:
	if (!completed_cmds) {
		atomic_dec(&reply_q->busy);
		return completed_cmds;
	}
	if (ioc->combined_reply_queue)
		writel(reply_q->reply_post_host_index | ((msix_index  & 7) <<
			MPI2_RPHI_MSIX_INDEX_SHIFT),
			ioc->replyPostRegisterIndex[msix_index/8]);
	else
		writel(reply_q->reply_post_host_index | (msix_index <<
			MPI2_RPHI_MSIX_INDEX_SHIFT),
			&ioc->chip->ReplyPostHostIndex);
	atomic_dec(&reply_q->busy);
	return completed_cmds;
}
static irqreturn_t
_base_interrupt(int irq, void *bus_id)
{
		struct adapter_reply_queue *reply_q = bus_id;
	struct MPT3SAS_ADAPTER *ioc = reply_q->ioc;
	if (ioc->mask_interrupts)
		return IRQ_NONE;
	if (reply_q->irq_poll_scheduled)
		return IRQ_HANDLED;
	return ((_base_process_reply_queue(reply_q) > 0) ?
			IRQ_HANDLED : IRQ_NONE);
}
static inline int
_base_is_controller_msix_enabled(struct MPT3SAS_ADAPTER *ioc)
{
	return (ioc->facts.IOCCapabilities &
	    MPI2_IOCFACTS_CAPABILITY_MSI_X_INDEX) && ioc->msix_enable;
}
void
mpt3sas_base_sync_reply_irqs(struct MPT3SAS_ADAPTER *ioc, u8 poll)
{
	struct adapter_reply_queue *reply_q;
	if (!_base_is_controller_msix_enabled(ioc))
		return;
	list_for_each_entry(reply_q, &ioc->reply_queue_list, list) {
		if (ioc->shost_recovery || ioc->remove_host ||
				ioc->pci_error_recovery)
			return;
		if (reply_q->msix_index == 0)
			continue;
		if (reply_q->is_iouring_poll_q) {
			_base_process_reply_queue(reply_q);
			continue;
		}
		synchronize_irq(pci_irq_vector(ioc->pdev, reply_q->msix_index));
																															}
	if (poll)
		_base_process_reply_queue(reply_q);
}
void
mpt3sas_base_release_callback_handler(u8 cb_idx)
{
	mpt_callbacks[cb_idx] = NULL;
}
u8
mpt3sas_base_register_callback_handler(MPT_CALLBACK cb_func)
{
	u8 cb_idx;
	for (cb_idx = MPT_MAX_CALLBACKS-1; cb_idx; cb_idx--)
		if (mpt_callbacks[cb_idx] == NULL)
			break;
	mpt_callbacks[cb_idx] = cb_func;
	return cb_idx;
}
void
mpt3sas_base_initialize_callback_handler(void)
{
	u8 cb_idx;
	for (cb_idx = 0; cb_idx < MPT_MAX_CALLBACKS; cb_idx++)
		mpt3sas_base_release_callback_handler(cb_idx);
}
static void
_base_build_zero_len_sge(struct MPT3SAS_ADAPTER *ioc, void *paddr)
{
	u32 flags_length = (u32)((MPI2_SGE_FLAGS_LAST_ELEMENT |
	    MPI2_SGE_FLAGS_END_OF_BUFFER | MPI2_SGE_FLAGS_END_OF_LIST |
	    MPI2_SGE_FLAGS_SIMPLE_ELEMENT) <<
	    MPI2_SGE_FLAGS_SHIFT);
	ioc->base_add_sg_single(paddr, flags_length, -1);
}
static void
_base_add_sg_single_32(void *paddr, u32 flags_length, dma_addr_t dma_addr)
{
	Mpi2SGESimple32_t *sgel = paddr;
	flags_length |= (MPI2_SGE_FLAGS_32_BIT_ADDRESSING |
	    MPI2_SGE_FLAGS_SYSTEM_ADDRESS) << MPI2_SGE_FLAGS_SHIFT;
	sgel->FlagsLength = cpu_to_le32(flags_length);
	sgel->Address = cpu_to_le32(dma_addr);
}
static void
_base_add_sg_single_64(void *paddr, u32 flags_length, dma_addr_t dma_addr)
{
	Mpi2SGESimple64_t *sgel = paddr;
	flags_length |= (MPI2_SGE_FLAGS_64_BIT_ADDRESSING |
	    MPI2_SGE_FLAGS_SYSTEM_ADDRESS) << MPI2_SGE_FLAGS_SHIFT;
	sgel->FlagsLength = cpu_to_le32(flags_length);
	sgel->Address = cpu_to_le64(dma_addr);
}
static struct chain_tracker *
_base_get_chain_buffer_tracker(struct MPT3SAS_ADAPTER *ioc,
			       struct scsi_cmnd *scmd)
{
	struct chain_tracker *chain_req;
	struct scsiio_tracker *st = scsi_cmd_priv(scmd);
	u16 smid = st->smid;
	u8 chain_offset =
	   atomic_read(&ioc->chain_lookup[smid - 1].chain_offset); 
	if (chain_offset == ioc->chains_needed_per_io)
		return NULL;
	chain_req = &ioc->chain_lookup[smid - 1].chains_per_smid[chain_offset];
	atomic_inc(&ioc->chain_lookup[smid - 1].chain_offset);
	return chain_req;
}
static void
_base_add_sg_single_ieee(void *paddr, u8 flags, u8 chain_offset, u32 length,
	dma_addr_t dma_addr)
{
	Mpi25IeeeSgeChain64_t *sgel = paddr;
	sgel->Flags = flags;
	sgel->NextChainOffset = chain_offset;
	sgel->Length = cpu_to_le32(length);
	sgel->Address = cpu_to_le64(dma_addr);
}
static void
_base_build_zero_len_sge_ieee(struct MPT3SAS_ADAPTER *ioc, void *paddr)
{
	u8 sgl_flags = (MPI2_IEEE_SGE_FLAGS_SIMPLE_ELEMENT |
		MPI2_IEEE_SGE_FLAGS_SYSTEM_ADDR |
		MPI25_IEEE_SGE_FLAGS_END_OF_LIST);
	_base_add_sg_single_ieee(paddr, sgl_flags, 0, 0, -1);
}
static int
_base_build_sg_scmd_ieee(struct MPT3SAS_ADAPTER *ioc,
	struct scsi_cmnd *scmd, u16 smid){
	Mpi25SCSIIORequest_t *mpi_request;
	dma_addr_t chain_dma;
	struct scatterlist *sg_scmd;
	void *sg_local, *chain;
	u32 chain_offset;
	u32 chain_length;
	int sges_left;
	u32 sges_in_segment;
	u8 simple_sgl_flags;
	u8 simple_sgl_flags_last;
	u8 chain_sgl_flags;
	struct chain_tracker *chain_req;
	mpi_request = mpt3sas_base_get_msg_frame(ioc, smid);
	simple_sgl_flags = MPI2_IEEE_SGE_FLAGS_SIMPLE_ELEMENT |
	    MPI2_IEEE_SGE_FLAGS_SYSTEM_ADDR;
	simple_sgl_flags_last = simple_sgl_flags |
	    MPI25_IEEE_SGE_FLAGS_END_OF_LIST;
	chain_sgl_flags = MPI2_IEEE_SGE_FLAGS_CHAIN_ELEMENT |
	    MPI2_IEEE_SGE_FLAGS_SYSTEM_ADDR;
	sg_scmd = scsi_sglist(scmd);
	sges_left = scsi_dma_map(scmd);
	if (sges_left < 0) {
		sdev_printk(KERN_ERR, scmd->device,
			"scsi_dma_map failed: request for %d bytes!\n",
			scsi_bufflen(scmd));
		return -ENOMEM;
	}
	sg_local = &mpi_request->SGL;
	sges_in_segment = (ioc->request_sz -
		   offsetof(Mpi25SCSIIORequest_t, SGL))/ioc->sge_size_ieee;
	if (sges_left <= sges_in_segment)
		goto fill_in_last_segment;
	mpi_request->ChainOffset = (sges_in_segment - 1 ) +
	    (offsetof(Mpi25SCSIIORequest_t, SGL)/ioc->sge_size_ieee); 
	while (sges_in_segment > 1) {
		_base_add_sg_single_ieee(sg_local, simple_sgl_flags, 0,
		    sg_dma_len(sg_scmd), sg_dma_address(sg_scmd));
		sg_scmd = sg_next(sg_scmd);
		sg_local += ioc->sge_size_ieee;
		sges_left--;
		sges_in_segment--;
	}
	chain_req = _base_get_chain_buffer_tracker(ioc, scmd);
	if (!chain_req)
		return -1;
	chain = chain_req->chain_buffer;
	chain_dma = chain_req->chain_buffer_dma;
	do {
		sges_in_segment = (sges_left <=
		    ioc->max_sges_in_chain_message) ? sges_left :
		    ioc->max_sges_in_chain_message;
		chain_offset = (sges_left == sges_in_segment) ?
		    0 : sges_in_segment;
		chain_length = sges_in_segment * ioc->sge_size_ieee;
		if (chain_offset)
			chain_length += ioc->sge_size_ieee;
		_base_add_sg_single_ieee(sg_local, chain_sgl_flags,
		    chain_offset, chain_length, chain_dma);
		sg_local = chain;
		if (!chain_offset)
			goto fill_in_last_segment;
		while (sges_in_segment) {
			_base_add_sg_single_ieee(sg_local, simple_sgl_flags, 0,
			    sg_dma_len(sg_scmd), sg_dma_address(sg_scmd));
			sg_scmd = sg_next(sg_scmd);
			sg_local += ioc->sge_size_ieee;
			sges_left--;
			sges_in_segment--;
		}
		chain_req = _base_get_chain_buffer_tracker(ioc, scmd);
		if (!chain_req)
			return -1;
		chain = chain_req->chain_buffer;
		chain_dma = chain_req->chain_buffer_dma;
	} while (1);
fill_in_last_segment:
	while (sges_left > 0) {
		if (sges_left == 1)
			_base_add_sg_single_ieee(sg_local,
			    simple_sgl_flags_last, 0, sg_dma_len(sg_scmd),
			    sg_dma_address(sg_scmd));
		else
			_base_add_sg_single_ieee(sg_local, simple_sgl_flags, 0,
			    sg_dma_len(sg_scmd), sg_dma_address(sg_scmd));
		sg_scmd = sg_next(sg_scmd);
		sg_local += ioc->sge_size_ieee;
		sges_left--;
	}
	return 0;
}
#define convert_to_kb(x) ((x) << (PAGE_SHIFT - 10))
static int
_base_config_dma_addressing(struct MPT3SAS_ADAPTER *ioc, struct pci_dev *pdev)
{
	struct sysinfo s;
				if (0 ||
	    sizeof(dma_addr_t) == 4 || ioc->use_32bit_dma ||
	    dma_get_required_mask(&pdev->dev) <= 32)
		ioc->dma_mask = 32;
	else if (ioc->hba_mpi_version_belonged > MPI2_VERSION)
		ioc->dma_mask = 63;
	else
		ioc->dma_mask = 64;
	if (dma_set_mask(&pdev->dev, DMA_BIT_MASK(ioc->dma_mask)) ||
	    dma_set_coherent_mask(&pdev->dev, DMA_BIT_MASK(ioc->dma_mask)))
		return -ENODEV;
	if (ioc->dma_mask > 32) {
		ioc->base_add_sg_single = &_base_add_sg_single_64;
		ioc->sge_size = sizeof(Mpi2SGESimple64_t);
	} else {
		ioc->base_add_sg_single = &_base_add_sg_single_32;
		ioc->sge_size = sizeof(Mpi2SGESimple32_t);
	}
	si_meminfo(&s);
	ioc_info(ioc, "%d BIT PCI BUS DMA ADDRESSING SUPPORTED, total mem (%ld kB)\n",
		ioc->dma_mask, convert_to_kb(s.totalram));
	return 0;
}
static int
_base_check_enable_msix(struct MPT3SAS_ADAPTER *ioc)
{
	int base;
	u16 message_control;
	base = pci_find_capability(ioc->pdev, PCI_CAP_ID_MSIX);
	if (!base) {
				return -EINVAL;
	}
											pci_read_config_word(ioc->pdev, base + 2, &message_control);
		ioc->msix_vector_count = (message_control & 0x3FF) + 1; 
				return 0;
}
void
mpt3sas_base_free_irq(struct MPT3SAS_ADAPTER *ioc)
{
	struct adapter_reply_queue *reply_q, *next;
	if (list_empty(&ioc->reply_queue_list))
		return;
	list_for_each_entry_safe(reply_q, next, &ioc->reply_queue_list, list) {
		list_del(&reply_q->list);
		if (reply_q->is_iouring_poll_q) {
			kfree(reply_q);
			continue;
		}
		if (ioc->smp_affinity_enable)
			irq_set_affinity_hint(pci_irq_vector(ioc->pdev,
			    reply_q->msix_index), NULL);
		free_irq(pci_irq_vector(ioc->pdev, reply_q->msix_index),
			 reply_q);
		kfree(reply_q);
	}
}
static int
_base_request_irq(struct MPT3SAS_ADAPTER *ioc, u8 index)
{
	struct pci_dev *pdev = ioc->pdev;
	struct adapter_reply_queue *reply_q;
	int r;
	reply_q =  kzalloc(sizeof(struct adapter_reply_queue), GFP_KERNEL);
	if (!reply_q) {
		ioc_err(ioc, "unable to allocate memory %zu!\n",
			sizeof(struct adapter_reply_queue));
		return -ENOMEM;
	}
	reply_q->ioc = ioc;
	reply_q->msix_index = index;
	atomic_set(&reply_q->busy, 0);
	if (ioc->msix_enable)
		snprintf(reply_q->name, MPT_NAME_LENGTH, "%s%d-msix%d",
		    ioc->driver_name, ioc->id, index);
	else
		snprintf(reply_q->name, MPT_NAME_LENGTH, "%s%d",
		    ioc->driver_name, ioc->id);
	r = request_irq(pci_irq_vector(pdev, index), _base_interrupt,
			IRQF_SHARED, reply_q->name, reply_q);
		if (r) {
		pr_err("%s: unable to allocate interrupt %d!\n",
		       reply_q->name, pci_irq_vector(pdev, index));
		kfree(reply_q);
		return -EBUSY;
	}
	INIT_LIST_HEAD(&reply_q->list);
	list_add_tail(&reply_q->list, &ioc->reply_queue_list);
	return 0;
}
static void
_base_assign_reply_queues(struct MPT3SAS_ADAPTER *ioc)
{
	unsigned int cpu, nr_cpus, nr_msix, index = 0;
	struct adapter_reply_queue *reply_q;
	int local_numa_node;
	int iopoll_q_count = ioc->reply_queue_count -
	    ioc->iopoll_q_start_index;
	if (!_base_is_controller_msix_enabled(ioc))
		return;
	memset(ioc->cpu_msix_table, 0, ioc->cpu_msix_table_sz);
	nr_cpus = num_online_cpus();
	nr_msix = ioc->reply_queue_count = min(ioc->reply_queue_count,
					       ioc->facts.MaxMSIxVectors);
	if (!nr_msix)
		return;
	if (ioc->smp_affinity_enable) {
		if (ioc->high_iops_queues) {
			local_numa_node = dev_to_node(&ioc->pdev->dev);
			for (index = 0; index < ioc->high_iops_queues;
			    index++) {
				irq_set_affinity_hint(pci_irq_vector(ioc->pdev,
				    index), cpumask_of_node(local_numa_node));
			}
		}
		list_for_each_entry(reply_q, &ioc->reply_queue_list, list) {
			const cpumask_t *mask;
			if (reply_q->msix_index < ioc->high_iops_queues ||
			    reply_q->msix_index >= ioc->iopoll_q_start_index)
				continue;
			mask = pci_irq_get_affinity(ioc->pdev,
			    reply_q->msix_index);
			pr_alert("reply_q->msix_index:%d",reply_q->msix_index);
			if (!mask) {
				ioc_warn(ioc, "no affinity for msi %x\n",
					 reply_q->msix_index);
				goto fall_back;
			}
			for_each_cpu_and(cpu, mask, cpu_online_mask) {
				if (cpu >= ioc->cpu_msix_table_sz)
					break;
				ioc->cpu_msix_table[cpu] = reply_q->msix_index;
			}
		}
		return;
	}
fall_back:
	cpu = cpumask_first(cpu_online_mask);
	nr_msix -= (ioc->high_iops_queues - iopoll_q_count);
	index = 0;
	list_for_each_entry(reply_q, &ioc->reply_queue_list, list) {
		unsigned int i, group = nr_cpus / nr_msix;
		if (reply_q->msix_index < ioc->high_iops_queues ||
		    reply_q->msix_index >= ioc->iopoll_q_start_index)
			continue;
		if (cpu >= nr_cpus)
			break;
		if (index < nr_cpus % nr_msix)
			group++;
		for (i = 0 ; i < group ; i++) {
			ioc->cpu_msix_table[cpu] = reply_q->msix_index;
			cpu = cpumask_next(cpu, cpu_online_mask);
		}
		index++;
	}
}
void
mpt3sas_base_disable_msix(struct MPT3SAS_ADAPTER *ioc)
{
	if (!ioc->msix_enable)
		return;
	pci_free_irq_vectors(ioc->pdev);
	ioc->msix_enable = 0;
	}
static int
_base_alloc_irq_vectors(struct MPT3SAS_ADAPTER *ioc)
{
	int i, irq_flags = PCI_IRQ_MSIX;
	struct irq_affinity desc = { .pre_vectors = ioc->high_iops_queues };
	struct irq_affinity *descp = &desc;
	int nr_msix_vectors = ioc->reply_queue_count;
	if (ioc->smp_affinity_enable)
		irq_flags |= PCI_IRQ_AFFINITY | PCI_IRQ_ALL_TYPES;
	else
		descp = NULL;
	i = pci_alloc_irq_vectors_affinity(ioc->pdev,
	    ioc->high_iops_queues,
	    nr_msix_vectors, irq_flags, descp);
		return i;
}
static int
_base_enable_msix(struct MPT3SAS_ADAPTER *ioc)
{
		int i;			
		_base_check_enable_msix(ioc);
	ioc_info(ioc, "MSI-X vectors supported: %d\n", ioc->msix_vector_count);
	ioc->reply_queue_count =
		min_t(int, ioc->cpu_count, ioc->msix_vector_count); 
	pr_err("%s, reply_queue_count=%d, cpu_count=%d, ioc->msix_vector_count=%d\n", 
		__func__, ioc->reply_queue_count, ioc->cpu_count, ioc->msix_vector_count);
		_base_alloc_irq_vectors(ioc); 
	ioc->msix_enable = 1;
	for (i = 0; i < ioc->reply_queue_count; i++) { 
				_base_request_irq(ioc, i);  
											}
	ioc_info(ioc, "High IOPs queues : %s\n",
			ioc->high_iops_queues ? "enabled" : "disabled");
	return 0;
}
static void
mpt3sas_base_unmap_resources(struct MPT3SAS_ADAPTER *ioc)
{
	struct pci_dev *pdev = ioc->pdev;
	mpt3sas_base_free_irq(ioc);
	mpt3sas_base_disable_msix(ioc);
	kfree(ioc->replyPostRegisterIndex);
	ioc->replyPostRegisterIndex = NULL;
	if (ioc->chip_phys) {
		iounmap(ioc->chip);
		ioc->chip_phys = 0;
	}
	if (pci_is_enabled(pdev)) {
		pci_release_selected_regions(ioc->pdev, ioc->bars);
		pci_disable_pcie_error_reporting(pdev);
		pci_disable_device(pdev);
	}
}
int
mpt3sas_base_map_resources(struct MPT3SAS_ADAPTER *ioc)
{
	struct pci_dev *pdev = ioc->pdev;
	u32 memap_sz;
	u32 pio_sz;
	int i, r = 0; 	u64 pio_chip = 0;
	phys_addr_t chip_phys = 0;
		pr_err("%s\n", __func__);
	ioc->bars = pci_select_bars(pdev, IORESOURCE_MEM); 
	if (pci_enable_device_mem(pdev)) { 
		ioc_warn(ioc, "pci_enable_device_mem: failed\n");
		ioc->bars = 0;
		return -ENODEV;
	}
	if (pci_request_selected_regions(pdev, ioc->bars,
	    ioc->driver_name)) {
		ioc_warn(ioc, "pci_request_selected_regions: failed\n");
		ioc->bars = 0;
		r = -ENODEV;
		goto out_fail;
	}
	pci_set_master(pdev);
	if (_base_config_dma_addressing(ioc, pdev) != 0) {
		ioc_warn(ioc, "no suitable DMA mask for %s\n", pci_name(pdev));
		r = -ENODEV;
		goto out_fail;
	}
	for (i = 0, memap_sz = 0, pio_sz = 0; (i < DEVICE_COUNT_RESOURCE) &&
	     (!memap_sz || !pio_sz); i++) {
		if (pci_resource_flags(pdev, i) & IORESOURCE_IO) {
			if (pio_sz)
				continue;
			pio_chip = (u64)pci_resource_start(pdev, i);
			pio_sz = pci_resource_len(pdev, i);
		} else if (pci_resource_flags(pdev, i) & IORESOURCE_MEM) {
			if (memap_sz) 
				continue;
			ioc->chip_phys = pci_resource_start(pdev, i);
			chip_phys = ioc->chip_phys;
			memap_sz = pci_resource_len(pdev, i);
			ioc->chip = ioremap(ioc->chip_phys, memap_sz);
		}
	}
	if (ioc->chip == NULL) {
		ioc_err(ioc,
		    "unable to map adapter memory! or resource not found\n");
		r = -EINVAL;
		goto out_fail;
	}
	mpt3sas_base_mask_interrupts(ioc);
	r = _base_get_ioc_facts(ioc);
	r = _base_enable_msix(ioc);
	if (r)
		goto out_fail;
	ioc->replyPostRegisterIndex = kcalloc(
		     ioc->combined_reply_index_count,
		     sizeof(resource_size_t *), GFP_KERNEL);
	if (!ioc->replyPostRegisterIndex) {
			ioc_err(ioc,
			    "allocation for replyPostRegisterIndex failed!\n");
			r = -ENOMEM;
			goto out_fail;
		}
	for (i = 0; i < ioc->combined_reply_index_count; i++) {
			ioc->replyPostRegisterIndex[i] = (resource_size_t *)
			     ((u8 __force *)&ioc->chip->Doorbell +
			     MPI25_SUP_REPLY_POST_HOST_INDEX_OFFSET +
			     (i * MPT3_SUP_REPLY_POST_HOST_INDEX_REG_OFFSET));
		}
	pci_save_state(pdev);
	return 0;
out_fail:
	mpt3sas_base_unmap_resources(ioc);
	return r;
}
void *
mpt3sas_base_get_msg_frame(struct MPT3SAS_ADAPTER *ioc, u16 smid)
{
	return (void *)(ioc->request + (smid * ioc->request_sz));
}
void *
mpt3sas_base_get_sense_buffer(struct MPT3SAS_ADAPTER *ioc, u16 smid)
{
	return (void *)(ioc->sense + ((smid - 1) * SCSI_SENSE_BUFFERSIZE));
}
__le32
mpt3sas_base_get_sense_buffer_dma(struct MPT3SAS_ADAPTER *ioc, u16 smid)
{
	return cpu_to_le32(ioc->sense_dma + ((smid - 1) *
	    SCSI_SENSE_BUFFERSIZE));
}
void *
mpt3sas_base_get_reply_virt_addr(struct MPT3SAS_ADAPTER *ioc, u32 phys_addr)
{
	if (!phys_addr)
		return NULL;
	return ioc->reply + (phys_addr - (u32)ioc->reply_dma);
}
static inline u8
_base_get_msix_index(struct MPT3SAS_ADAPTER *ioc,
	struct scsi_cmnd *scmd)
{
	if (scmd && ioc->shost->nr_hw_queues > 1) {
		u32 tag = blk_mq_unique_tag(scsi_cmd_to_rq(scmd));
		return blk_mq_unique_tag_to_hwq(tag) +
			ioc->high_iops_queues;
	}
	return ioc->cpu_msix_table[raw_smp_processor_id()];
}
u16
mpt3sas_base_get_smid(struct MPT3SAS_ADAPTER *ioc, u8 cb_idx)
{
	unsigned long flags;
	struct request_tracker *request;
	u16 smid; 
	spin_lock_irqsave(&ioc->scsi_lookup_lock, flags);
	if (list_empty(&ioc->internal_free_list)) {
		spin_unlock_irqrestore(&ioc->scsi_lookup_lock, flags);
		ioc_err(ioc, "%s: smid not available\n", __func__);
		return 0;
	}
	request = list_entry(ioc->internal_free_list.next,
	    struct request_tracker, tracker_list);
	request->cb_idx = cb_idx; 
	smid = request->smid; 
	list_del(&request->tracker_list);
	spin_unlock_irqrestore(&ioc->scsi_lookup_lock, flags);
	return smid;
}
u16
mpt3sas_base_get_smid_scsiio(struct MPT3SAS_ADAPTER *ioc, u8 cb_idx,
	struct scsi_cmnd *scmd)
{
	struct scsiio_tracker *request = scsi_cmd_priv(scmd);
	u16 smid;
	u32 tag, unique_tag;
	unique_tag = blk_mq_unique_tag(scsi_cmd_to_rq(scmd));
	tag = blk_mq_unique_tag_to_tag(unique_tag);
	ioc->io_queue_num[tag] = blk_mq_unique_tag_to_hwq(unique_tag);
	smid = tag + 1;
	request->cb_idx = cb_idx;
	request->smid = smid;
	request->scmd = scmd;
	INIT_LIST_HEAD(&request->chain_list);
	return smid;
}
void mpt3sas_base_clear_st(struct MPT3SAS_ADAPTER *ioc,
			   struct scsiio_tracker *st)
{
	if (WARN_ON(st->smid == 0))
		return;
	st->cb_idx = 0xFF;
	st->direct_io = 0;
	st->scmd = NULL;
	atomic_set(&ioc->chain_lookup[st->smid - 1].chain_offset, 0);
	st->smid = 0;
}
void
mpt3sas_base_free_smid(struct MPT3SAS_ADAPTER *ioc, u16 smid)
{
	unsigned long flags;
	int i;
	if (smid < ioc->hi_priority_smid) {
		struct scsiio_tracker *st;
		void *request;
		st = _get_st_from_smid(ioc, smid);
		request = mpt3sas_base_get_msg_frame(ioc, smid);
		memset(request, 0, ioc->request_sz);
		mpt3sas_base_clear_st(ioc, st);
				ioc->io_queue_num[smid - 1] = 0;
		return;
	}
	spin_lock_irqsave(&ioc->scsi_lookup_lock, flags);
	if (smid < ioc->internal_smid) {
		i = smid - ioc->hi_priority_smid;
		ioc->hpr_lookup[i].cb_idx = 0xFF;
		list_add(&ioc->hpr_lookup[i].tracker_list, &ioc->hpr_free_list);
	} else if (smid <= ioc->hba_queue_depth) {
		i = smid - ioc->internal_smid;
		ioc->internal_lookup[i].cb_idx = 0xFF;
		list_add(&ioc->internal_lookup[i].tracker_list,
		    &ioc->internal_free_list);
	}
	spin_unlock_irqrestore(&ioc->scsi_lookup_lock, flags);
}
static inline void
_base_mpi_ep_writeq(__u64 b, volatile void __iomem *addr,
					spinlock_t *writeq_lock)
{
	unsigned long flags;
	spin_lock_irqsave(writeq_lock, flags);
	__raw_writel((u32)(b), addr);
	__raw_writel((u32)(b >> 32), (addr + 4));
	spin_unlock_irqrestore(writeq_lock, flags);
}
#if defined(writeq) && defined(CONFIG_64BIT)
static inline void
_base_writeq(__u64 b, volatile void __iomem *addr, spinlock_t *writeq_lock)
{
	wmb();
	__raw_writeq(b, addr);
	barrier();
}
#else
static inline void
_base_writeq(__u64 b, volatile void __iomem *addr, spinlock_t *writeq_lock)
{
	_base_mpi_ep_writeq(b, addr, writeq_lock);
}
#endif
static u8
_base_set_and_get_msix_index(struct MPT3SAS_ADAPTER *ioc, u16 smid)
{
	struct scsiio_tracker *st = NULL;
	if (smid < ioc->hi_priority_smid)
		st = _get_st_from_smid(ioc, smid);
	if (st == NULL)
		return  _base_get_msix_index(ioc, NULL);
	st->msix_io = ioc->get_msix_index_for_smlio(ioc, st->scmd);
	return st->msix_io;
}
static void
_base_put_smid_scsi_io(struct MPT3SAS_ADAPTER *ioc, u16 smid, u16 handle)
{
	Mpi2RequestDescriptorUnion_t descriptor;
	u64 *request = (u64 *)&descriptor;
	descriptor.SCSIIO.RequestFlags = MPI2_REQ_DESCRIPT_FLAGS_SCSI_IO;
	descriptor.SCSIIO.MSIxIndex = _base_set_and_get_msix_index(ioc, smid);
	descriptor.SCSIIO.SMID = cpu_to_le16(smid);
	descriptor.SCSIIO.DevHandle = cpu_to_le16(handle);
	descriptor.SCSIIO.LMID = 0;
	_base_writeq(*request, &ioc->chip->RequestDescriptorPostLow,
	    &ioc->scsi_lookup_lock);
	}
static void
_base_put_smid_default(struct MPT3SAS_ADAPTER *ioc, u16 smid)
{
	Mpi2RequestDescriptorUnion_t descriptor; 
		u64 *request;
	request = (u64 *)&descriptor;
	descriptor.Default.RequestFlags = MPI2_REQ_DESCRIPT_FLAGS_DEFAULT_TYPE;
	descriptor.Default.MSIxIndex = _base_set_and_get_msix_index(ioc, smid);
	descriptor.Default.SMID = cpu_to_le16(smid);
	descriptor.Default.LMID = 0;
	descriptor.Default.DescriptorTypeDependent = 0;
							_base_writeq(*request, &ioc->chip->RequestDescriptorPostLow,
				&ioc->scsi_lookup_lock);
}
static int _base_assign_fw_reported_qd(struct MPT3SAS_ADAPTER *ioc)
{
	Mpi2ConfigReply_t mpi_reply;
	Mpi2SasIOUnitPage1_t *sas_iounit_pg1 = NULL;
		int sz;
	int rc = 0;
	ioc->max_wideport_qd = MPT3SAS_SAS_QUEUE_DEPTH;
	ioc->max_narrowport_qd = MPT3SAS_SAS_QUEUE_DEPTH;
	ioc->max_sata_qd = MPT3SAS_SATA_QUEUE_DEPTH;
	ioc->max_nvme_qd = MPT3SAS_NVME_QUEUE_DEPTH;
	if (!ioc->is_gen35_ioc)
		goto out;
	sz = offsetof(Mpi2SasIOUnitPage1_t, PhyData);
	sas_iounit_pg1 = kzalloc(sz, GFP_KERNEL);
	if (!sas_iounit_pg1) {
		pr_err("%s: failure at %s:%d/%s()!\n",
		    ioc->name, __FILE__, __LINE__, __func__);
		return rc;
	}
	rc = mpt3sas_config_get_sas_iounit_pg1(ioc, &mpi_reply,
	    sas_iounit_pg1, sz);
	if (rc) {
		pr_err("%s: failure at %s:%d/%s()!\n",
		    ioc->name, __FILE__, __LINE__, __func__);
		goto out;
	}
	ioc->max_wideport_qd =
	    (le16_to_cpu(sas_iounit_pg1->SASWideMaxQueueDepth)) ?
	    le16_to_cpu(sas_iounit_pg1->SASWideMaxQueueDepth) :
	    MPT3SAS_SAS_QUEUE_DEPTH;
	ioc->max_narrowport_qd =
	    (le16_to_cpu(sas_iounit_pg1->SASNarrowMaxQueueDepth)) ?
	    le16_to_cpu(sas_iounit_pg1->SASNarrowMaxQueueDepth) :
	    MPT3SAS_SAS_QUEUE_DEPTH;
	ioc->max_sata_qd = (sas_iounit_pg1->SATAMaxQDepth) ?
	    sas_iounit_pg1->SATAMaxQDepth : MPT3SAS_SATA_QUEUE_DEPTH;
											out:
					kfree(sas_iounit_pg1);
	return rc;
}
static int
_base_static_config_pages(struct MPT3SAS_ADAPTER *ioc)
{
	Mpi2ConfigReply_t mpi_reply;
	u32 iounit_pg1_flags;
		int rc;
	ioc->nvme_abort_timeout = 30;
	rc = mpt3sas_config_get_manufacturing_pg11(ioc, &mpi_reply,
	    &ioc->manu_pg11);
	if (rc)
		return rc;
	if (!ioc->is_gen35_ioc && ioc->manu_pg11.EEDPTagMode == 0) {
		pr_err("%s: overriding NVDATA EEDPTagMode setting\n",
		    ioc->name);
		ioc->manu_pg11.EEDPTagMode &= ~0x3;
		ioc->manu_pg11.EEDPTagMode |= 0x1;
		mpt3sas_config_set_manufacturing_pg11(ioc, &mpi_reply,
		    &ioc->manu_pg11);
	}
													ioc->time_sync_interval =
	    ioc->manu_pg11.TimeSyncInterval & MPT3SAS_TIMESYNC_MASK;
	if (ioc->time_sync_interval) {
		if (ioc->manu_pg11.TimeSyncInterval & MPT3SAS_TIMESYNC_UNIT_MASK)
			ioc->time_sync_interval =
			    ioc->time_sync_interval * SECONDS_PER_HOUR;
		else
			ioc->time_sync_interval =
			    ioc->time_sync_interval * SECONDS_PER_MIN;
									} else {
		if (ioc->is_gen35_ioc)
			ioc_warn(ioc,
			    "TimeSync Interval in Manuf page-11 is not enabled. Periodic Time-Sync will be disabled\n");
	}
	rc = _base_assign_fw_reported_qd(ioc);
	if (rc)
		return rc;
										rc = mpt3sas_config_get_iounit_pg0(ioc, &mpi_reply, &ioc->iounit_pg0);
	if (rc)
		return rc;
	rc = mpt3sas_config_get_iounit_pg1(ioc, &mpi_reply, &ioc->iounit_pg1);
	if (rc)
		return rc;
	rc = mpt3sas_config_get_iounit_pg8(ioc, &mpi_reply, &ioc->iounit_pg8);
	if (rc)
		return rc;
	iounit_pg1_flags = le32_to_cpu(ioc->iounit_pg1.Flags);
	if ((ioc->facts.IOCCapabilities &
	    MPI2_IOCFACTS_CAPABILITY_TASK_SET_FULL_HANDLING))
		iounit_pg1_flags &=
		    ~MPI2_IOUNITPAGE1_DISABLE_TASK_SET_FULL_HANDLING;
	else
		iounit_pg1_flags |=
		    MPI2_IOUNITPAGE1_DISABLE_TASK_SET_FULL_HANDLING;
	ioc->iounit_pg1.Flags = cpu_to_le32(iounit_pg1_flags);
	rc = mpt3sas_config_set_iounit_pg1(ioc, &mpi_reply, &ioc->iounit_pg1);
	if (rc)
		return rc;
	if (ioc->iounit_pg8.NumSensors)
		ioc->temp_sensors_count = ioc->iounit_pg8.NumSensors;
																															return 0;
}
static void
_base_release_memory_pools(struct MPT3SAS_ADAPTER *ioc)
{
	int i = 0;
	int j = 0;
	int dma_alloc_count = 0;
	struct chain_tracker *ct;
	int count = ioc->rdpq_array_enable ? ioc->reply_queue_count : 1;
	if (ioc->request) {
		dma_free_coherent(&ioc->pdev->dev, ioc->request_dma_sz,
		    ioc->request,  ioc->request_dma);
								ioc->request = NULL;
	}
	if (ioc->sense) {
		dma_pool_free(ioc->sense_dma_pool, ioc->sense, ioc->sense_dma);
		dma_pool_destroy(ioc->sense_dma_pool);
								ioc->sense = NULL;
	}
	if (ioc->reply) {
		dma_pool_free(ioc->reply_dma_pool, ioc->reply, ioc->reply_dma);
		dma_pool_destroy(ioc->reply_dma_pool);
								ioc->reply = NULL;
	}
	if (ioc->reply_free) {
		dma_pool_free(ioc->reply_free_dma_pool, ioc->reply_free,
		    ioc->reply_free_dma);
		dma_pool_destroy(ioc->reply_free_dma_pool);
								ioc->reply_free = NULL;
	}
	if (ioc->reply_post) {
		dma_alloc_count = DIV_ROUND_UP(count,
				RDPQ_MAX_INDEX_IN_ONE_CHUNK);
		for (i = 0; i < count; i++) {
			if (i % RDPQ_MAX_INDEX_IN_ONE_CHUNK == 0
			    && dma_alloc_count) {
				if (ioc->reply_post[i].reply_post_free) {
					dma_pool_free(
					    ioc->reply_post_free_dma_pool,
					    ioc->reply_post[i].reply_post_free,
					ioc->reply_post[i].reply_post_free_dma);
																				ioc->reply_post[i].reply_post_free =
									NULL;
				}
				--dma_alloc_count;
			}
		}
		dma_pool_destroy(ioc->reply_post_free_dma_pool);
																		kfree(ioc->reply_post);
	}
	kfree(ioc->hpr_lookup);
	ioc->hpr_lookup = NULL;
	kfree(ioc->internal_lookup);
	ioc->internal_lookup = NULL;
	if (ioc->chain_lookup) {
		for (i = 0; i < ioc->scsiio_depth; i++) {
			for (j = ioc->chains_per_prp_buffer;
			    j < ioc->chains_needed_per_io; j++) {
				ct = &ioc->chain_lookup[i].chains_per_smid[j];
				if (ct && ct->chain_buffer)
					dma_pool_free(ioc->chain_dma_pool,
						ct->chain_buffer,
						ct->chain_buffer_dma);
			}
			kfree(ioc->chain_lookup[i].chains_per_smid);
		}
		dma_pool_destroy(ioc->chain_dma_pool);
		kfree(ioc->chain_lookup);
		ioc->chain_lookup = NULL;
	}
	kfree(ioc->io_queue_num);
	ioc->io_queue_num = NULL;
}
static int
mpt3sas_check_same_4gb_region(long reply_pool_start_address, u32 pool_sz)
{
	long reply_pool_end_address;
	reply_pool_end_address = reply_pool_start_address + pool_sz;
	if (upper_32_bits(reply_pool_start_address) ==
		upper_32_bits(reply_pool_end_address))
		return 1;
	else
		return 0;
}
static inline int
_base_reduce_hba_queue_depth(struct MPT3SAS_ADAPTER *ioc)
{
	int reduce_sz = 64;
	if ((ioc->hba_queue_depth - reduce_sz) >
	    (ioc->internal_depth + INTERNAL_SCSIIO_CMDS_COUNT)) {
		ioc->hba_queue_depth -= reduce_sz;
		return 0;
	} else
		return -ENOMEM;
}
static int
_base_allocate_chain_dma_pool(struct MPT3SAS_ADAPTER *ioc, u32 sz)
{
	int i = 0, j = 0;
	struct chain_tracker *ctr;
	ioc->chain_dma_pool = dma_pool_create("chain pool", &ioc->pdev->dev,
	    ioc->chain_segment_sz, 16, 0);
	if (!ioc->chain_dma_pool)
		return -ENOMEM;
	for (i = 0; i < ioc->scsiio_depth; i++) {
		for (j = ioc->chains_per_prp_buffer;
		    j < ioc->chains_needed_per_io; j++) {
			ctr = &ioc->chain_lookup[i].chains_per_smid[j];
			ctr->chain_buffer = dma_pool_alloc(ioc->chain_dma_pool,
			    GFP_KERNEL, &ctr->chain_buffer_dma);
			if (!ctr->chain_buffer)
				return -EAGAIN;
			if (!mpt3sas_check_same_4gb_region((long)
			    ctr->chain_buffer, ioc->chain_segment_sz)) {
				ioc_err(ioc,
				    "Chain buffers are not in same 4G !!! Chain buff (0x%p) dma = (0x%llx)\n",
				    ctr->chain_buffer,
				    (unsigned long long)ctr->chain_buffer_dma);
				ioc->use_32bit_dma = true;
				return -EAGAIN;
			}
		}
	}
						return 0;
}
static int
_base_allocate_sense_dma_pool(struct MPT3SAS_ADAPTER *ioc, u32 sz)
{
	ioc->sense_dma_pool =
	    dma_pool_create("sense pool", &ioc->pdev->dev, sz, 4, 0);
	if (!ioc->sense_dma_pool)
		return -ENOMEM;
	ioc->sense = dma_pool_alloc(ioc->sense_dma_pool,
	    GFP_KERNEL, &ioc->sense_dma);
	if (!ioc->sense)
		return -EAGAIN;
	if (!mpt3sas_check_same_4gb_region((long)ioc->sense, sz)) {
								ioc->use_32bit_dma = true;
		return -EAGAIN;
	}
	ioc_info(ioc,
	    "sense pool(0x%p) - dma(0x%llx): depth(%d), element_size(%d), pool_size (%d kB)\n",
	    ioc->sense, (unsigned long long)ioc->sense_dma,
	    ioc->scsiio_depth, SCSI_SENSE_BUFFERSIZE, sz/1024);
	return 0;
}
static int
_base_allocate_reply_pool(struct MPT3SAS_ADAPTER *ioc, u32 sz)
{
	ioc->reply_dma_pool = dma_pool_create("reply pool",
	    &ioc->pdev->dev, sz, 4, 0);
	if (!ioc->reply_dma_pool)
		return -ENOMEM;
	ioc->reply = dma_pool_alloc(ioc->reply_dma_pool, GFP_KERNEL,
	    &ioc->reply_dma);
	if (!ioc->reply)
		return -EAGAIN;
	if (!mpt3sas_check_same_4gb_region((long)ioc->reply_free, sz)) {
								ioc->use_32bit_dma = true;
		return -EAGAIN;
	}
	ioc->reply_dma_min_address = (u32)(ioc->reply_dma);
	ioc->reply_dma_max_address = (u32)(ioc->reply_dma) + sz;
	ioc_info(ioc,
	    "reply pool(0x%p) - dma(0x%llx): depth(%d), frame_size(%d), pool_size(%d kB)\n",
	    ioc->reply, (unsigned long long)ioc->reply_dma,
	    ioc->reply_free_queue_depth, ioc->reply_sz, sz/1024);
	return 0;
}
static int
_base_allocate_reply_free_dma_pool(struct MPT3SAS_ADAPTER *ioc, u32 sz)
{
	ioc->reply_free_dma_pool = dma_pool_create(
	    "reply_free pool", &ioc->pdev->dev, sz, 16, 0);
	if (!ioc->reply_free_dma_pool)
		return -ENOMEM;
	ioc->reply_free = dma_pool_alloc(ioc->reply_free_dma_pool,
	    GFP_KERNEL, &ioc->reply_free_dma);
	if (!ioc->reply_free)
		return -EAGAIN;
	if (!mpt3sas_check_same_4gb_region((long)ioc->reply_free, sz)) {
								ioc->use_32bit_dma = true;
		return -EAGAIN;
	}
	memset(ioc->reply_free, 0, sz);
							return 0;
}
static int
base_alloc_rdpq_dma_pool(struct MPT3SAS_ADAPTER *ioc, int sz)
{
	int i = 0;
	u32 dma_alloc_count = 0;
	int reply_post_free_sz = ioc->reply_post_queue_depth *
		sizeof(Mpi2DefaultReplyDescriptor_t);
	int count = ioc->rdpq_array_enable ? ioc->reply_queue_count : 1;
	ioc->reply_post = kcalloc(count, sizeof(struct reply_post_struct),
			GFP_KERNEL); 
	if (!ioc->reply_post)
		return -ENOMEM;
	dma_alloc_count = DIV_ROUND_UP(count,
				RDPQ_MAX_INDEX_IN_ONE_CHUNK); 
	ioc->reply_post_free_dma_pool =
		dma_pool_create("reply_post_free pool",
		    &ioc->pdev->dev, sz, 16, 0);  
	if (!ioc->reply_post_free_dma_pool)
		return -ENOMEM;
	for (i = 0; i < count; i++) {
		if ((i % RDPQ_MAX_INDEX_IN_ONE_CHUNK == 0) && dma_alloc_count) {
			ioc->reply_post[i].reply_post_free =
			    dma_pool_zalloc(ioc->reply_post_free_dma_pool, 
				GFP_KERNEL,
				&ioc->reply_post[i].reply_post_free_dma); 
			if (!ioc->reply_post[i].reply_post_free)
				return -ENOMEM;
			if (!mpt3sas_check_same_4gb_region(
				(long)ioc->reply_post[i].reply_post_free, sz)) {
																												return -EAGAIN;
			}
			dma_alloc_count--;
		} else {
			ioc->reply_post[i].reply_post_free =
			    (Mpi2ReplyDescriptorsUnion_t *)
			    ((long)ioc->reply_post[i-1].reply_post_free
			    + reply_post_free_sz);
			ioc->reply_post[i].reply_post_free_dma =
			    (dma_addr_t)
			    (ioc->reply_post[i-1].reply_post_free_dma +
			    reply_post_free_sz);
		}
	}
	return 0;
}
static int
_base_allocate_memory_pools(struct MPT3SAS_ADAPTER *ioc)
{
	struct mpt3sas_facts *facts;
	u16 max_sge_elements;
	u16 chains_needed_per_io;
	u32 sz, total_sz, reply_post_free_sz;	u32 retry_sz;
	u32 rdpq_sz = 0, sense_sz = 0;
	u16 max_request_credit;	unsigned short sg_tablesize;
	u16 sge_size;
	int i;
	int ret = 0, rc = 0;
		pr_err("%s\n", __func__);
	retry_sz = 0;
	facts = &ioc->facts;
												sg_tablesize = MPT3SAS_SG_DEPTH; 
																					ioc->shost->sg_tablesize = sg_tablesize; 
		pr_err("%s sg table size=%d\n", __func__, ioc->shost->sg_tablesize);
	ioc->internal_depth = min_t(int, (facts->HighPriorityCredit + (5)),
		(facts->RequestCredit / 4)); 
										ioc->hi_priority_depth = ioc->internal_depth - (5); 
											max_request_credit = min_t(u16, facts->RequestCredit,
		    MAX_HBA_QUEUE_DEPTH); 
	ioc->hba_queue_depth = max_request_credit + ioc->hi_priority_depth;
	pr_err("%s ioc->hba_queue_depth=%d\n", __func__, ioc->hba_queue_depth);
	ioc->request_sz = facts->IOCRequestFrameSize * 4; 
	ioc->reply_sz = facts->ReplyFrameSize * 4; 
	if (ioc->hba_mpi_version_belonged != MPI2_VERSION) {
		if (facts->IOCMaxChainSegmentSize)
			ioc->chain_segment_sz =
					facts->IOCMaxChainSegmentSize *
					MAX_CHAIN_ELEMT_SZ; 
									} 	
	sge_size = max_t(u16, ioc->sge_size, ioc->sge_size_ieee); 
	pr_err("%s sge_size=%d\n", __func__, sge_size);
	total_sz = 0;
	max_sge_elements = ioc->request_sz - ((sizeof(Mpi2SCSIIORequest_t) - sizeof(Mpi2SGEIOUnion_t)) + sge_size);
	ioc->max_sges_in_main_message = max_sge_elements/sge_size; 
	max_sge_elements = ioc->chain_segment_sz - sge_size;
	ioc->max_sges_in_chain_message = max_sge_elements/sge_size; 
	chains_needed_per_io = \
		((ioc->shost->sg_tablesize - ioc->max_sges_in_main_message) / ioc->max_sges_in_chain_message) + 1; 
							ioc->chains_needed_per_io = chains_needed_per_io; 
	ioc->reply_free_queue_depth = ioc->hba_queue_depth + 64; 
		ioc->reply_post_queue_depth = ioc->hba_queue_depth +
			ioc->reply_free_queue_depth +  1; 
		if (ioc->reply_post_queue_depth % 16)
			ioc->reply_post_queue_depth += 16 -
				(ioc->reply_post_queue_depth % 16); 
	ioc_info(ioc,
	    "scatter gather: sge_in_main_msg(%d), sge_per_chain(%d), "
	    "sge_per_io(%d), chains_per_io(%d)\n",
	    ioc->max_sges_in_main_message,
	    ioc->max_sges_in_chain_message,
	    ioc->shost->sg_tablesize,
	    ioc->chains_needed_per_io);
	reply_post_free_sz = ioc->reply_post_queue_depth *
	    sizeof(Mpi2DefaultReplyDescriptor_t);
	pr_err("%s reply descriptor的长度=%d(字节)\n", __func__, reply_post_free_sz);
	rdpq_sz = reply_post_free_sz * RDPQ_MAX_INDEX_IN_ONE_CHUNK; 
	if ((_base_is_controller_msix_enabled(ioc) && !ioc->rdpq_array_enable)
	    || (ioc->reply_queue_count < RDPQ_MAX_INDEX_IN_ONE_CHUNK))
			rdpq_sz = reply_post_free_sz * ioc->reply_queue_count; 	
	pr_err("%s ioc->reply_queue_count=%d(descriptor)\n", __func__, ioc->reply_queue_count);
	ret = base_alloc_rdpq_dma_pool(ioc, rdpq_sz);
																	if(ret != 0)
		pr_alert("%s 我就不信内存分配会失败，这一步失败了就别玩了\n", __func__);
	total_sz = rdpq_sz * (!ioc->rdpq_array_enable ? 1 :
	    DIV_ROUND_UP(ioc->reply_queue_count, RDPQ_MAX_INDEX_IN_ONE_CHUNK));
	ioc->scsiio_depth = ioc->hba_queue_depth -
	    ioc->hi_priority_depth - ioc->internal_depth;
	pr_err("%s 检查几个队列深度 hba_queue_depth=%d, hi_priority_depth=%d, internal_depth=%d\n", 
		__func__, ioc->hba_queue_depth, ioc->hi_priority_depth, ioc->internal_depth);
	ioc->shost->can_queue = ioc->scsiio_depth - INTERNAL_SCSIIO_CMDS_COUNT;
				pr_err("%s 最后得到的can queue=%d\n", __func__, ioc->shost->can_queue);
	ioc->chain_depth = ioc->chains_needed_per_io * ioc->scsiio_depth;
	sz = ((ioc->scsiio_depth + 1) * ioc->request_sz);
	sz += (ioc->hi_priority_depth * ioc->request_sz);
	sz += (ioc->internal_depth * ioc->request_sz);
	ioc->request_dma_sz = sz; 
	ioc->request = dma_alloc_coherent(&ioc->pdev->dev, sz,
			&ioc->request_dma, GFP_KERNEL); 
	if (!ioc->request) {
		pr_alert("%s ioc->request 请求队列分配GG了, 如果这个GG那就别玩了\n", __func__);
																			}
	ioc->hi_priority = ioc->request + ((ioc->scsiio_depth + 1) *
	    ioc->request_sz);
	ioc->hi_priority_dma = ioc->request_dma + ((ioc->scsiio_depth + 1) *
	    ioc->request_sz); 
	ioc->internal = ioc->hi_priority + (ioc->hi_priority_depth *
	    ioc->request_sz);
	ioc->internal_dma = ioc->hi_priority_dma + (ioc->hi_priority_depth *
	    ioc->request_sz);
	total_sz += sz; 
	ioc->chain_depth = min_t(u32, ioc->chain_depth, MAX_CHAIN_DEPTH);
	sz = ioc->scsiio_depth * sizeof(struct chain_lookup); 
	ioc->chain_lookup = kzalloc(sz, GFP_KERNEL); 
	if (!ioc->chain_lookup) {
		ioc_err(ioc, "chain_lookup: __get_free_pages failed 内存分配gg\n");
			}
	sz = ioc->chains_needed_per_io * sizeof(struct chain_tracker);
	for (i = 0; i < ioc->scsiio_depth; i++) {
		ioc->chain_lookup[i].chains_per_smid = kzalloc(sz, GFP_KERNEL); 
		if (!ioc->chain_lookup[i].chains_per_smid) {
			ioc_err(ioc, "chain_lookup: kzalloc failed 内存分配gg\n");
					}
	}
	ioc->hpr_lookup = kcalloc(ioc->hi_priority_depth,
	    sizeof(struct request_tracker), GFP_KERNEL);
	if (!ioc->hpr_lookup) {
		ioc_err(ioc, "hpr_lookup: kcalloc failed 内存分配gg\n");
			}
	ioc->hi_priority_smid = ioc->scsiio_depth + 1;
	ioc->internal_lookup = kcalloc(ioc->internal_depth,
	    sizeof(struct request_tracker), GFP_KERNEL);
	if (!ioc->internal_lookup) {
		ioc_err(ioc, "internal_lookup: kcalloc failed 内存分配gg\n");
			}
	ioc->internal_smid = ioc->hi_priority_smid + ioc->hi_priority_depth;
	ioc->io_queue_num = kcalloc(ioc->scsiio_depth,
	    sizeof(u16), GFP_KERNEL);
	if (!ioc->io_queue_num)
		pr_alert("%s ioc->io_queue_num 内存分配gg了\n", __func__);
	ioc->chains_per_prp_buffer = 0;
	rc = _base_allocate_chain_dma_pool(ioc, ioc->chain_segment_sz); 
					if(rc)
		pr_err("%s _base_allocate_chain_dma_pool gg就重新搞吧\n", __func__);
	total_sz += ioc->chain_segment_sz * ((ioc->chains_needed_per_io -
		ioc->chains_per_prp_buffer) * ioc->scsiio_depth);
	sense_sz = ioc->scsiio_depth * SCSI_SENSE_BUFFERSIZE; 
	rc = _base_allocate_sense_dma_pool(ioc, sense_sz);
					if(rc)
		pr_err("%s _base_allocate_sense_dma_pool gg就重新搞吧\n", __func__);
	total_sz += sense_sz; 
	ioc_info(ioc,
	    "sense pool(0x%p)- dma(0x%llx): depth(%d),"
	    "element_size(%d), pool_size(%d kB)\n",
	    ioc->sense, (unsigned long long)ioc->sense_dma, ioc->scsiio_depth,
	    SCSI_SENSE_BUFFERSIZE, sz / 1024);
	sz = ioc->reply_free_queue_depth * ioc->reply_sz; 
	rc = _base_allocate_reply_pool(ioc, sz); 
					if(rc)
		pr_err("%s _base_allocate_reply_pool gg就重新搞吧\n", __func__);
	total_sz += sz;
	sz = ioc->reply_free_queue_depth * 4; 
	rc = _base_allocate_reply_free_dma_pool(ioc, sz); 
					if(rc)
		pr_err("%s _base_allocate_reply_free_dma_pool gg就重新搞吧\n", __func__);
	total_sz += sz;
												ioc->config_page = dma_alloc_coherent(&ioc->pdev->dev,
			ioc->config_page_sz, &ioc->config_page_dma, GFP_KERNEL);
	if (!ioc->config_page) {
		ioc_err(ioc, "config page: dma_pool_alloc failed\n");
			}
	ioc_info(ioc, "Allocated physical memory: size(%d kB)\n",
		 total_sz / 1024);
	ioc_info(ioc, "Current Controller Queue Depth(%d),Max Controller Queue Depth(%d)\n",
		 ioc->shost->can_queue, facts->RequestCredit);
	ioc_info(ioc, "Scatter Gather Elements per IO(%d)\n",
		 ioc->shost->sg_tablesize);
	return 0;
}
u32
mpt3sas_base_get_iocstate(struct MPT3SAS_ADAPTER *ioc, int cooked)
{
	u32 s, sc;
	s = ioc->base_readl(&ioc->chip->Doorbell);
	sc = s & MPI2_IOC_STATE_MASK;
	return cooked ? sc : s;
}
static int
_base_wait_on_iocstate(struct MPT3SAS_ADAPTER *ioc, u32 ioc_state, int timeout)
{
	u32 count, cntdn;
	u32 current_state;
	count = 0;
	cntdn = 1000 * timeout;
	do {
		current_state = mpt3sas_base_get_iocstate(ioc, 1);
		if (current_state == ioc_state)
			return 0;
		if (count && current_state == MPI2_IOC_STATE_FAULT)
			break;
		if (count && current_state == MPI2_IOC_STATE_COREDUMP)
			break;
		usleep_range(1000, 1500);
		count++;
	} while (--cntdn);
	return current_state;
}
static inline void
_base_dump_reg_set(struct MPT3SAS_ADAPTER *ioc)
{
	unsigned int i, sz = 256;
	u32 __iomem *reg = (u32 __iomem *)ioc->chip;
	ioc_info(ioc, "System Register set:\n");
	for (i = 0; i < (sz / sizeof(u32)); i++)
		pr_info("%08x: %08x\n", (i * 4), readl(&reg[i]));
}
static int
_base_wait_for_doorbell_int(struct MPT3SAS_ADAPTER *ioc, int timeout)
{
	u32 cntdn, count;
	u32 int_status;
	count = 0;
	cntdn = 1000 * timeout;
	do {
		int_status = ioc->base_readl(&ioc->chip->HostInterruptStatus);
		if (int_status & MPI2_HIS_IOC2SYS_DB_STATUS) {
												return 0;
		}
		usleep_range(1000, 1500);
		count++;
	} while (--cntdn);
	ioc_err(ioc, "%s: failed due to timeout count(%d), int_status(%x)!\n",
		__func__, count, int_status);
	return -EFAULT;
}
static int
_base_spin_on_doorbell_int(struct MPT3SAS_ADAPTER *ioc, int timeout)
{
	u32 cntdn, count;
	u32 int_status;
	count = 0;
	cntdn = 2000 * timeout;
	do {
		int_status = ioc->base_readl(&ioc->chip->HostInterruptStatus);
		if (int_status & MPI2_HIS_IOC2SYS_DB_STATUS) {
												return 0;
		}
		udelay(500);
		count++;
	} while (--cntdn);
	ioc_err(ioc, "%s: failed due to timeout count(%d), int_status(%x)!\n",
		__func__, count, int_status);
	return -EFAULT;
}
static int
_base_wait_for_doorbell_ack(struct MPT3SAS_ADAPTER *ioc, int timeout)
{
	u32 cntdn, count;
	u32 int_status;
	count = 0;
	cntdn = 1000 * timeout;
	do {
		int_status = ioc->base_readl(&ioc->chip->HostInterruptStatus);
		if (!(int_status & MPI2_HIS_SYS2IOC_DB_STATUS)) {
												return 0;
		}
		usleep_range(1000, 1500);
		count++;
	} while (--cntdn);
	ioc_err(ioc, "%s: failed due to timeout count(%d), int_status(%x)!\n",
		__func__, count, int_status);
	return -EFAULT;
}
static int
_base_wait_for_doorbell_not_used(struct MPT3SAS_ADAPTER *ioc, int timeout)
{
	u32 cntdn, count;
	u32 doorbell_reg;
	count = 0;
	cntdn = 1000 * timeout;
	do {
		doorbell_reg = ioc->base_readl(&ioc->chip->Doorbell);
		if (!(doorbell_reg & MPI2_DOORBELL_USED)) {
												return 0;
		}
		usleep_range(1000, 1500);
		count++;
	} while (--cntdn);
	ioc_err(ioc, "%s: failed due to timeout count(%d), doorbell_reg(%x)!\n",
		__func__, count, doorbell_reg);
	return -EFAULT;
}
static int
_base_send_ioc_reset(struct MPT3SAS_ADAPTER *ioc, u8 reset_type, int timeout)
{
	u32 ioc_state;
	int r = 0;
	if (reset_type != MPI2_FUNCTION_IOC_MESSAGE_UNIT_RESET) {
		ioc_err(ioc, "%s: unknown reset_type\n", __func__);
		return -EFAULT;
	}
	if (!(ioc->facts.IOCCapabilities &
	   MPI2_IOCFACTS_CAPABILITY_EVENT_REPLAY))
		return -EFAULT;
	ioc_info(ioc, "sending message unit reset !!\n");
	writel(reset_type << MPI2_DOORBELL_FUNCTION_SHIFT,
	    &ioc->chip->Doorbell);
	if ((_base_wait_for_doorbell_ack(ioc, 15))) {
		r = -EFAULT;
		goto out;
	}
	ioc_state = _base_wait_on_iocstate(ioc, MPI2_IOC_STATE_READY, timeout);
	if (ioc_state) {
		ioc_err(ioc, "%s: failed going to ready state (ioc_state=0x%x)\n",
			__func__, ioc_state);
		r = -EFAULT;
		goto out;
	}
out:
	ioc_info(ioc, "message unit reset: %s\n",
		 r == 0 ? "SUCCESS" : "FAILED");
	return r;
}
int
mpt3sas_wait_for_ioc(struct MPT3SAS_ADAPTER *ioc, int timeout)
{
	int wait_state_count = 0;
	u32 ioc_state;
	do {
		ioc_state = mpt3sas_base_get_iocstate(ioc, 1);
		if (ioc_state == MPI2_IOC_STATE_OPERATIONAL)
			break;
		if (ioc->is_driver_loading)
			return -ETIME;
		ssleep(1);
		ioc_info(ioc, "%s: waiting for operational state(count=%d)\n",
				__func__, ++wait_state_count);
	} while (--timeout);
	if (!timeout) {
		ioc_err(ioc, "%s: failed due to ioc not operational\n", __func__);
		return -EFAULT;
	}
	if (wait_state_count)
		ioc_info(ioc, "ioc is operational\n");
	return 0;
}
static int
_base_handshake_req_reply_wait(struct MPT3SAS_ADAPTER *ioc, int request_bytes,
	u32 *request, int reply_bytes, u16 *reply, int timeout)
{
	MPI2DefaultReply_t *default_reply = (MPI2DefaultReply_t *)reply;
	int i;
	u8 failed;
	if ((ioc->base_readl(&ioc->chip->Doorbell) & MPI2_DOORBELL_USED)) {
		ioc_err(ioc, "doorbell is in use (line=%d)\n", __LINE__);
		return -EFAULT;
	}
	if (ioc->base_readl(&ioc->chip->HostInterruptStatus) &
	    MPI2_HIS_IOC2SYS_DB_STATUS)
		writel(0, &ioc->chip->HostInterruptStatus);
	writel(((MPI2_FUNCTION_HANDSHAKE << MPI2_DOORBELL_FUNCTION_SHIFT) |
	    ((request_bytes/4) << MPI2_DOORBELL_ADD_DWORDS_SHIFT)),
	    &ioc->chip->Doorbell);
	pr_err("%s first send to ioc = 0x%x!\n", 
		__func__, ((MPI2_FUNCTION_HANDSHAKE << MPI2_DOORBELL_FUNCTION_SHIFT) | ((request_bytes / 4) << MPI2_DOORBELL_ADD_DWORDS_SHIFT)));
	if ((_base_spin_on_doorbell_int(ioc, 5))) {
		ioc_err(ioc, "doorbell handshake int failed (line=%d)\n",
			__LINE__);
		return -EFAULT;
	}
	writel(0, &ioc->chip->HostInterruptStatus); 
	if ((_base_wait_for_doorbell_ack(ioc, 5))) {
		ioc_err(ioc, "doorbell handshake ack failed (line=%d)\n",
			__LINE__);
		return -EFAULT;
	}
	for (i = 0, failed = 0; i < request_bytes/4 && !failed; i++) {
		writel(cpu_to_le32(request[i]), &ioc->chip->Doorbell);
		if ((_base_wait_for_doorbell_ack(ioc, 5))) 
			failed = 1;
	}
	if (failed) {
		ioc_err(ioc, "doorbell handshake sending request failed (line=%d)\n",
			__LINE__);
		return -EFAULT;
	}
	if ((_base_wait_for_doorbell_int(ioc, timeout))) {
		ioc_err(ioc, "doorbell handshake int failed (line=%d)\n",
			__LINE__);
		return -EFAULT;
	}
	reply[0] = le16_to_cpu(ioc->base_readl(&ioc->chip->Doorbell)
	    & MPI2_DOORBELL_DATA_MASK);
	writel(0, &ioc->chip->HostInterruptStatus);
	if ((_base_wait_for_doorbell_int(ioc, 5))) {
		ioc_err(ioc, "doorbell handshake int failed (line=%d)\n",
			__LINE__);
		return -EFAULT;
	}
	reply[1] = le16_to_cpu(ioc->base_readl(&ioc->chip->Doorbell)
	    & MPI2_DOORBELL_DATA_MASK);
	writel(0, &ioc->chip->HostInterruptStatus);
	for (i = 2; i < default_reply->MsgLength * 2; i++)  { 
		if ((_base_wait_for_doorbell_int(ioc, 5))) {
			ioc_err(ioc, "doorbell handshake int failed (line=%d)\n",
				__LINE__);
			return -EFAULT;
		}
		if (i >=  reply_bytes/2) 
			ioc->base_readl(&ioc->chip->Doorbell);
		else
			reply[i] = le16_to_cpu(
			    ioc->base_readl(&ioc->chip->Doorbell)
			    & MPI2_DOORBELL_DATA_MASK);
		writel(0, &ioc->chip->HostInterruptStatus);
	}
	_base_wait_for_doorbell_int(ioc, 5);
	if (_base_wait_for_doorbell_not_used(ioc, 5) != 0) {
							}
	writel(0, &ioc->chip->HostInterruptStatus);
								return 0;
}
static int
_base_wait_for_iocstate(struct MPT3SAS_ADAPTER *ioc, int timeout)
{
	u32 ioc_state;
	int rc;
		pr_err("%s\n", __func__);
	if (ioc->pci_error_recovery) {
								return -EFAULT;
	}
	ioc_state = mpt3sas_base_get_iocstate(ioc, 0); 
	pr_err("%s ioc_state=0x%x\n", __func__, ioc_state);
	if (((ioc_state & MPI2_IOC_STATE_MASK) == MPI2_IOC_STATE_READY) ||
	    (ioc_state & MPI2_IOC_STATE_MASK) == MPI2_IOC_STATE_OPERATIONAL)
		return 0;
	return rc;
}
static int
_base_get_ioc_facts(struct MPT3SAS_ADAPTER *ioc)
{
	Mpi2IOCFactsRequest_t mpi_request;
	Mpi2IOCFactsReply_t mpi_reply;
	struct mpt3sas_facts *facts;
	int mpi_reply_sz, mpi_request_sz, r;
		pr_err("%s\n", __func__);
	r = _base_wait_for_iocstate(ioc, 10); 
	if (r) {
								return r;
	}
	pr_err("%s ioc ready!\n", __func__);
	mpi_reply_sz = sizeof(Mpi2IOCFactsReply_t);
	mpi_request_sz = sizeof(Mpi2IOCFactsRequest_t);
	pr_err("%s mpi_reply_sz=%d, mpi_request_sz=%d!\n", __func__, mpi_reply_sz, mpi_request_sz);
	memset(&mpi_request, 0, mpi_request_sz);
	mpi_request.Function = MPI2_FUNCTION_IOC_FACTS; 
	r = _base_handshake_req_reply_wait(ioc, mpi_request_sz,
	    (u32 *)&mpi_request, mpi_reply_sz, (u16 *)&mpi_reply, 5);
	if (r != 0) {
		ioc_err(ioc, "%s: handshake failed (r=%d)\n", __func__, r);
		return r;
	}
	facts = &ioc->facts;
	memset(facts, 0, sizeof(struct mpt3sas_facts));
	facts->MsgVersion = le16_to_cpu(mpi_reply.MsgVersion);
	facts->HeaderVersion = le16_to_cpu(mpi_reply.HeaderVersion);
	facts->VP_ID = mpi_reply.VP_ID;
	facts->VF_ID = mpi_reply.VF_ID;
	facts->IOCExceptions = le16_to_cpu(mpi_reply.IOCExceptions);
	pr_err("%s facts->IOCExceptions=%d!\n", __func__, facts->IOCExceptions);
	facts->MaxChainDepth = mpi_reply.MaxChainDepth; 
	pr_err("%s facts->MaxChainDepth=%d!\n", __func__, facts->MaxChainDepth);
	facts->WhoInit = mpi_reply.WhoInit;
	facts->NumberOfPorts = mpi_reply.NumberOfPorts; 
	facts->MaxMSIxVectors = mpi_reply.MaxMSIxVectors; 
	pr_err("%s facts->MaxMSIxVectors=%d!\n", __func__, facts->MaxMSIxVectors);
				facts->RequestCredit = le16_to_cpu(mpi_reply.RequestCredit); 
	pr_err("%s HBA队列深度的一部分 facts->RequestCredit=%d!\n", __func__, facts->RequestCredit);
	facts->MaxReplyDescriptorPostQueueDepth =
	    le16_to_cpu(mpi_reply.MaxReplyDescriptorPostQueueDepth); 
	pr_err("%s HBA reply描述符队列的深度 facts->MaxReplyDescriptorPostQueueDepth=%d!\n", 
		__func__, facts->MaxReplyDescriptorPostQueueDepth);
	facts->ProductID = le16_to_cpu(mpi_reply.ProductID); 
	facts->IOCCapabilities = le32_to_cpu(mpi_reply.IOCCapabilities); 
									facts->FWVersion.Word = le32_to_cpu(mpi_reply.FWVersion.Word);
	facts->IOCRequestFrameSize =
	    le16_to_cpu(mpi_reply.IOCRequestFrameSize); 
	pr_err("%s facts->IOCRequestFrameSize=%d!\n", __func__, facts->IOCRequestFrameSize);
	if (ioc->hba_mpi_version_belonged != MPI2_VERSION) {
		facts->IOCMaxChainSegmentSize =
			le16_to_cpu(mpi_reply.IOCMaxChainSegmentSize); 
		pr_err("%s facts->IOCMaxChainSegmentSize=%d!\n", __func__, facts->IOCMaxChainSegmentSize);
	}
			ioc->shost->max_id = -1;
				facts->HighPriorityCredit =
	    le16_to_cpu(mpi_reply.HighPriorityCredit); 
	facts->ReplyFrameSize = mpi_reply.ReplyFrameSize; 
	facts->MaxDevHandle = le16_to_cpu(mpi_reply.MaxDevHandle); 
	facts->CurrentHostPageSize = mpi_reply.CurrentHostPageSize; 
	ioc->page_size = 1 << facts->CurrentHostPageSize; 
	if (ioc->page_size == 1) {
		ioc_info(ioc, "CurrentHostPageSize is 0: Setting default host page size to 4k\n");
		ioc->page_size = 1 << MPT3SAS_HOST_PAGE_SIZE_4K;
	}
	pr_err("%s offset facts->CurrentHostPageSize=%d, page size=%d!\n", 
		__func__, facts->CurrentHostPageSize, 1 << facts->CurrentHostPageSize);
											return 0;
}
static int
_base_send_ioc_init(struct MPT3SAS_ADAPTER *ioc)
{
	Mpi2IOCInitRequest_t mpi_request;
	Mpi2IOCInitReply_t mpi_reply;
	int  r = 0;	ktime_t current_time;
	u16 ioc_status;
		pr_err("%s\n", __func__);
	memset(&mpi_request, 0, sizeof(Mpi2IOCInitRequest_t));
	mpi_request.Function = MPI2_FUNCTION_IOC_INIT; 
	mpi_request.WhoInit = MPI2_WHOINIT_HOST_DRIVER;
	mpi_request.VF_ID = 0;
	mpi_request.VP_ID = 0;
	mpi_request.MsgVersion = cpu_to_le16(ioc->hba_mpi_version_belonged);
	mpi_request.HeaderVersion = cpu_to_le16(MPI2_HEADER_VERSION);
	mpi_request.HostPageSize = MPT3SAS_HOST_PAGE_SIZE_4K;
	if (_base_is_controller_msix_enabled(ioc))
		mpi_request.HostMSIxVectors = ioc->reply_queue_count; 
	mpi_request.SystemRequestFrameSize = \
		cpu_to_le16(ioc->request_sz/4); 
	mpi_request.ReplyDescriptorPostQueueDepth =
	    cpu_to_le16(ioc->reply_post_queue_depth); 
	mpi_request.ReplyFreeQueueDepth =
	    cpu_to_le16(ioc->reply_free_queue_depth); 
	mpi_request.SenseBufferAddressHigh =
	    cpu_to_le32((u64)ioc->sense_dma >> 32);
	mpi_request.SystemReplyAddressHigh =
	    cpu_to_le32((u64)ioc->reply_dma >> 32);
	mpi_request.SystemRequestFrameBaseAddress =
	    cpu_to_le64((u64)ioc->request_dma);
	mpi_request.ReplyFreeQueueAddress =
	    cpu_to_le64((u64)ioc->reply_free_dma);
		mpi_request.ReplyDescriptorPostQueueAddress =
		    cpu_to_le64((u64)ioc->reply_post[0].reply_post_free_dma);
	mpi_request.ConfigurationFlags |=
	    cpu_to_le16(MPI26_IOCINIT_CFGFLAGS_COREDUMP_ENABLE);
	current_time = ktime_get_real();
	mpi_request.TimeStamp = cpu_to_le64(ktime_to_ms(current_time));
	r = _base_handshake_req_reply_wait(ioc,
	    sizeof(Mpi2IOCInitRequest_t), (u32 *)&mpi_request,
	    sizeof(Mpi2IOCInitReply_t), (u16 *)&mpi_reply, 30);
	if (r != 0) {
		ioc_err(ioc, "%s: handshake failed (r=%d)\n", __func__, r);
		return r;
	}
	ioc_status = le16_to_cpu(mpi_reply.IOCStatus) & MPI2_IOCSTATUS_MASK;
	if (ioc_status != MPI2_IOCSTATUS_SUCCESS ||
	    mpi_reply.IOCLogInfo) {
		ioc_err(ioc, "%s: failed\n", __func__);
		r = -EIO;
	}
	ioc->timestamp_update_count = 0;
	return r;
}
u8
mpt3sas_port_enable_done(struct MPT3SAS_ADAPTER *ioc, u16 smid, u8 msix_index,
	u32 reply)
{
	MPI2DefaultReply_t *mpi_reply;
	u16 ioc_status;
	pr_err("%s\n", __func__);
	if (ioc->port_enable_cmds.status == MPT3_CMD_NOT_USED)
		return 1;
	mpi_reply = mpt3sas_base_get_reply_virt_addr(ioc, reply);
	if (!mpi_reply)
		return 1;
	if (mpi_reply->Function != MPI2_FUNCTION_PORT_ENABLE)
		return 1;
	ioc->port_enable_cmds.status &= ~MPT3_CMD_PENDING;
	ioc->port_enable_cmds.status |= MPT3_CMD_COMPLETE;
	ioc->port_enable_cmds.status |= MPT3_CMD_REPLY_VALID;
	memcpy(ioc->port_enable_cmds.reply, mpi_reply, mpi_reply->MsgLength*4);
	ioc_status = le16_to_cpu(mpi_reply->IOCStatus) & MPI2_IOCSTATUS_MASK;
	if (ioc_status != MPI2_IOCSTATUS_SUCCESS)
		ioc->port_enable_failed = 1;
	if (ioc->port_enable_cmds.status & MPT3_CMD_COMPLETE_ASYNC) { 
		ioc->port_enable_cmds.status &= ~MPT3_CMD_COMPLETE_ASYNC; 
		if (ioc_status == MPI2_IOCSTATUS_SUCCESS) {
			mpt3sas_port_enable_complete(ioc);
			return 1;
		} else {
			ioc->start_scan_failed = ioc_status;
			ioc->start_scan = 0;
			return 1;
		}
	}
	complete(&ioc->port_enable_cmds.done);
	return 1;
}
static int
_base_send_port_enable(struct MPT3SAS_ADAPTER *ioc)
{
	Mpi2PortEnableRequest_t *mpi_request;
	Mpi2PortEnableReply_t *mpi_reply;
	int r = 0;
	u16 smid;
	u16 ioc_status;
	ioc_info(ioc, "sending port enable !!\n");
	if (ioc->port_enable_cmds.status & MPT3_CMD_PENDING) {
		ioc_err(ioc, "%s: internal command already in use\n", __func__);
		return -EAGAIN;
	}
	smid = mpt3sas_base_get_smid(ioc, ioc->port_enable_cb_idx);
	if (!smid) {
		ioc_err(ioc, "%s: failed obtaining a smid\n", __func__);
		return -EAGAIN;
	}
	ioc->port_enable_cmds.status = MPT3_CMD_PENDING;
	mpi_request = mpt3sas_base_get_msg_frame(ioc, smid);
	ioc->port_enable_cmds.smid = smid;
	memset(mpi_request, 0, sizeof(Mpi2PortEnableRequest_t));
	mpi_request->Function = MPI2_FUNCTION_PORT_ENABLE;
	init_completion(&ioc->port_enable_cmds.done);
	ioc->put_smid_default(ioc, smid);
	wait_for_completion_timeout(&ioc->port_enable_cmds.done, 300*HZ);
	if (!(ioc->port_enable_cmds.status & MPT3_CMD_COMPLETE)) {
		ioc_err(ioc, "%s: timeout\n", __func__);
						if (ioc->port_enable_cmds.status & MPT3_CMD_RESET)
			r = -EFAULT;
		else
			r = -ETIME;
		goto out;
	}
	mpi_reply = ioc->port_enable_cmds.reply;
	ioc_status = le16_to_cpu(mpi_reply->IOCStatus) & MPI2_IOCSTATUS_MASK;
	if (ioc_status != MPI2_IOCSTATUS_SUCCESS) {
		ioc_err(ioc, "%s: failed with (ioc_status=0x%08x)\n",
			__func__, ioc_status);
		r = -EFAULT;
		goto out;
	}
out:
	ioc->port_enable_cmds.status = MPT3_CMD_NOT_USED;
	ioc_info(ioc, "port enable: %s\n", r == 0 ? "SUCCESS" : "FAILED");
	return r;
}
int
mpt3sas_port_enable(struct MPT3SAS_ADAPTER *ioc)
{
	Mpi2PortEnableRequest_t *mpi_request;
	u16 smid;
	if (ioc->port_enable_cmds.status & MPT3_CMD_PENDING) {
		ioc_err(ioc, "%s: internal command already in use\n", __func__);
		return -EAGAIN;
	}
	smid = mpt3sas_base_get_smid(ioc, ioc->port_enable_cb_idx);
	if (!smid) {
		ioc_err(ioc, "%s: failed obtaining a smid\n", __func__);
		return -EAGAIN;
	}
	ioc->drv_internal_flags |= MPT_DRV_INTERNAL_FIRST_PE_ISSUED;
	ioc->port_enable_cmds.status = MPT3_CMD_PENDING;
	ioc->port_enable_cmds.status |= MPT3_CMD_COMPLETE_ASYNC;
	mpi_request = mpt3sas_base_get_msg_frame(ioc, smid); 
	ioc->port_enable_cmds.smid = smid; 
	memset(mpi_request, 0, sizeof(Mpi2PortEnableRequest_t));
	mpi_request->Function = MPI2_FUNCTION_PORT_ENABLE;
	ioc->put_smid_default(ioc, smid);
	return 0;
}
static void
_base_unmask_events(struct MPT3SAS_ADAPTER *ioc, u16 event)
{
	u32 desired_event;
	if (event >= 128)
		return;
	desired_event = (1 << (event % 32));
	if (event < 32)
		ioc->event_masks[0] &= ~desired_event;
	else if (event < 64)
		ioc->event_masks[1] &= ~desired_event;
	else if (event < 96)
		ioc->event_masks[2] &= ~desired_event;
	else if (event < 128)
		ioc->event_masks[3] &= ~desired_event;
}
static int
_base_event_notification(struct MPT3SAS_ADAPTER *ioc)
{
	Mpi2EventNotificationRequest_t *mpi_request;
	u16 smid;
	int r = 0;
	int i, issue_diag_reset = 0;
	if (ioc->base_cmds.status & MPT3_CMD_PENDING) {
		ioc_err(ioc, "%s: internal command already in use\n", __func__);
		return -EAGAIN;
	}
	smid = mpt3sas_base_get_smid(ioc, ioc->base_cb_idx);
	if (!smid) {
		ioc_err(ioc, "%s: failed obtaining a smid\n", __func__);
		return -EAGAIN;
	}
	ioc->base_cmds.status = MPT3_CMD_PENDING;
	mpi_request = mpt3sas_base_get_msg_frame(ioc, smid);
	ioc->base_cmds.smid = smid;
	memset(mpi_request, 0, sizeof(Mpi2EventNotificationRequest_t));
	mpi_request->Function = MPI2_FUNCTION_EVENT_NOTIFICATION;
	mpi_request->VF_ID = 0; 
	mpi_request->VP_ID = 0;
	for (i = 0; i < MPI2_EVENT_NOTIFY_EVENTMASK_WORDS; i++)
		mpi_request->EventMasks[i] =
		    cpu_to_le32(ioc->event_masks[i]);
	init_completion(&ioc->base_cmds.done);
	ioc->put_smid_default(ioc, smid);
	wait_for_completion_timeout(&ioc->base_cmds.done, 30*HZ);
	if (!(ioc->base_cmds.status & MPT3_CMD_COMPLETE)) {
		ioc_err(ioc, "%s: timeout\n", __func__);
						if (ioc->base_cmds.status & MPT3_CMD_RESET)
			r = -EFAULT;
		else
			issue_diag_reset = 1;
	} 
			ioc->base_cmds.status = MPT3_CMD_NOT_USED;
								return r;
}
int
mpt3sas_base_make_ioc_ready(struct MPT3SAS_ADAPTER *ioc, enum reset_type type)
{
	u32 ioc_state;
	int rc;
	int count;
	pr_err("%s\n", __func__);
	ioc_state = mpt3sas_base_get_iocstate(ioc, 0); 
	count = 0;
	if ((ioc_state & MPI2_IOC_STATE_MASK) == MPI2_IOC_STATE_RESET) {
		while ((ioc_state & MPI2_IOC_STATE_MASK) !=
		    MPI2_IOC_STATE_READY) {
			if (count++ == 10) {
				ioc_err(ioc, "%s: failed going to ready state (ioc_state=0x%x)\n",
					__func__, ioc_state);
				return -EFAULT;
			}
			ssleep(1);
			ioc_state = mpt3sas_base_get_iocstate(ioc, 0);
		}
	}
	if ((ioc_state & MPI2_IOC_STATE_MASK) == MPI2_IOC_STATE_READY)
		return 0;
	if ((ioc_state & MPI2_IOC_STATE_MASK) == MPI2_IOC_STATE_OPERATIONAL)
		if (!(_base_send_ioc_reset(ioc, MPI2_FUNCTION_IOC_MESSAGE_UNIT_RESET, 15)))
			return 0;
	return rc;
}
static int
_base_make_ioc_operational(struct MPT3SAS_ADAPTER *ioc)
{
	int r, i, index; 	unsigned long	flags;
	u32 reply_address;
	u16 smid;
		struct _sc_list *delayed_sc, *delayed_sc_next;
	struct _event_ack_list *delayed_event_ack, *delayed_event_ack_next;
		struct adapter_reply_queue *reply_q;
	Mpi2ReplyDescriptorsUnion_t *reply_post_free_contig;
	list_for_each_entry_safe(delayed_sc, delayed_sc_next,
	    &ioc->delayed_sc_list, list) {
		list_del(&delayed_sc->list);
		kfree(delayed_sc);
	}
	list_for_each_entry_safe(delayed_event_ack, delayed_event_ack_next,
	    &ioc->delayed_event_ack_list, list) {
		list_del(&delayed_event_ack->list);
		kfree(delayed_event_ack);
	}
	spin_lock_irqsave(&ioc->scsi_lookup_lock, flags);
	INIT_LIST_HEAD(&ioc->hpr_free_list);
	smid = ioc->hi_priority_smid;
	for (i = 0; i < ioc->hi_priority_depth; i++, smid++) {
		ioc->hpr_lookup[i].cb_idx = 0xFF;
		ioc->hpr_lookup[i].smid = smid;
		list_add_tail(&ioc->hpr_lookup[i].tracker_list,
		    &ioc->hpr_free_list);
	}
	INIT_LIST_HEAD(&ioc->internal_free_list);
	smid = ioc->internal_smid;
	for (i = 0; i < ioc->internal_depth; i++, smid++) {
		ioc->internal_lookup[i].cb_idx = 0xFF;
		ioc->internal_lookup[i].smid = smid;
		list_add_tail(&ioc->internal_lookup[i].tracker_list,
		    &ioc->internal_free_list);
	}
	spin_unlock_irqrestore(&ioc->scsi_lookup_lock, flags);
	for (i = 0, reply_address = (u32)ioc->reply_dma ;
	    i < ioc->reply_free_queue_depth ; i++, reply_address +=
	    ioc->reply_sz) {
		ioc->reply_free[i] = cpu_to_le32(reply_address);
							}
	if (ioc->is_driver_loading)
		_base_assign_reply_queues(ioc); 
	index = 0;
	reply_post_free_contig = ioc->reply_post[0].reply_post_free; 
	list_for_each_entry(reply_q, &ioc->reply_queue_list, list) {
											reply_q->reply_post_free = reply_post_free_contig;
			reply_post_free_contig += ioc->reply_post_queue_depth;
		reply_q->reply_post_host_index = 0;
		for (i = 0; i < ioc->reply_post_queue_depth; i++)
			reply_q->reply_post_free[i].Words =
			    cpu_to_le64(ULLONG_MAX); 
		if (!_base_is_controller_msix_enabled(ioc))
			goto skip_init_reply_post_free_queue;
	}
skip_init_reply_post_free_queue:
	r = _base_send_ioc_init(ioc);
	if (r) {
		pr_alert("%s _base_send_ioc_init gg 重新搞吧\n", __func__);
							}
	ioc->reply_free_host_index = ioc->reply_free_queue_depth - 1;
	writel(ioc->reply_free_host_index, &ioc->chip->ReplyFreeHostIndex); 
	pr_err("%s ioc->reply_free_host_index=%d\n", __func__, ioc->reply_free_host_index); 
	list_for_each_entry(reply_q, &ioc->reply_queue_list, list) {
		if (ioc->combined_reply_queue)
			writel((reply_q->msix_index & 7)<<
			   MPI2_RPHI_MSIX_INDEX_SHIFT,
			   ioc->replyPostRegisterIndex[reply_q->msix_index/8]);
		else
			writel(reply_q->msix_index <<
				MPI2_RPHI_MSIX_INDEX_SHIFT,
				&ioc->chip->ReplyPostHostIndex); 
		if (!_base_is_controller_msix_enabled(ioc))
			goto skip_init_reply_post_host_index;
	}
skip_init_reply_post_host_index:
	mpt3sas_base_unmask_interrupts(ioc);
	r = _base_static_config_pages(ioc);
	if (r)
		return r;
	r = _base_event_notification(ioc);
	if (r)
		return r;
	if (!ioc->shost_recovery) {
		ioc->wait_for_discovery_to_complete = 0;
		pr_alert("%d",ioc->wait_for_discovery_to_complete);
		return r; 
	}
	r = _base_send_port_enable(ioc); 
	if (r)
		return r;
	return r;
}
void
mpt3sas_base_free_resources(struct MPT3SAS_ADAPTER *ioc)
{
	mutex_lock(&ioc->pci_access_mutex);
	if (ioc->chip_phys && ioc->chip) {
		mpt3sas_base_mask_interrupts(ioc);
		ioc->shost_recovery = 1;
		mpt3sas_base_make_ioc_ready(ioc, SOFT_RESET);
		ioc->shost_recovery = 0;
	}
	mpt3sas_base_unmap_resources(ioc);
	mutex_unlock(&ioc->pci_access_mutex);
	return;
}
int
mpt3sas_base_attach(struct MPT3SAS_ADAPTER *ioc)
{
	int r, i;	int cpu_id, last_cpu_id = 0;
	pr_err("%s\n", __func__);
	ioc->cpu_count = num_online_cpus(); 
	for_each_online_cpu(cpu_id)
		last_cpu_id = cpu_id; 
	pr_err("%s cpu=%d, id=%d\n", __func__, ioc->cpu_count, last_cpu_id);
	ioc->cpu_msix_table_sz = last_cpu_id + 1;
	ioc->cpu_msix_table = kzalloc(ioc->cpu_msix_table_sz, GFP_KERNEL);
	ioc->reply_queue_count = 1;
	if (!ioc->cpu_msix_table) {
		ioc_info(ioc, "Allocation for cpu_msix_table failed!!!\n");
		r = -ENOMEM;
		goto out_free_resources;
	}
	ioc->smp_affinity_enable = smp_affinity_enable;
		ioc->use_32bit_dma = false;
	ioc->dma_mask = 64;
					ioc->base_readl = &_base_readl; 
	r = mpt3sas_base_map_resources(ioc);
	if (r)
		goto out_free_resources;
	pci_set_drvdata(ioc->pdev, ioc->shost);
		ioc->build_sg_scmd = &_base_build_sg_scmd_ieee;
						ioc->build_zero_len_sge = &_base_build_zero_len_sge_ieee;
		ioc->sge_size_ieee = sizeof(Mpi2IeeeSgeSimple64_t);
											ioc->get_msix_index_for_smlio = &_base_get_msix_index;
												ioc->put_smid_default = &_base_put_smid_default; 
															ioc->put_smid_scsi_io = &_base_put_smid_scsi_io; 
		ioc->build_zero_len_sge_mpi = &_base_build_zero_len_sge;
	r = mpt3sas_base_make_ioc_ready(ioc, SOFT_RESET);
	if (r)
		goto out_free_resources;
	r = _base_allocate_memory_pools(ioc);
	if (r)
		goto out_free_resources;
					ioc->thresh_hold = ioc->hba_queue_depth/4; 
	ioc->pd_handles_sz = (ioc->facts.MaxDevHandle / 8);
	if (ioc->facts.MaxDevHandle % 8)
		ioc->pd_handles_sz++;
	ioc->pd_handles = kzalloc(ioc->pd_handles_sz,
	    GFP_KERNEL);
	if (!ioc->pd_handles) {
		r = -ENOMEM;
		goto out_free_resources;
	}
	ioc->blocking_handles = kzalloc(ioc->pd_handles_sz,
	    GFP_KERNEL);
	if (!ioc->blocking_handles) {
		r = -ENOMEM;
		goto out_free_resources;
	}
	ioc->pend_os_device_add_sz = (ioc->facts.MaxDevHandle / 8);
	if (ioc->facts.MaxDevHandle % 8)
		ioc->pend_os_device_add_sz++;
	ioc->pend_os_device_add = kzalloc(ioc->pend_os_device_add_sz,
	    GFP_KERNEL);
	if (!ioc->pend_os_device_add) {
		r = -ENOMEM;
		goto out_free_resources;
	}
	ioc->device_remove_in_progress_sz = ioc->pend_os_device_add_sz;
	ioc->device_remove_in_progress =
		kzalloc(ioc->device_remove_in_progress_sz, GFP_KERNEL);
	if (!ioc->device_remove_in_progress) {
		r = -ENOMEM;
		goto out_free_resources;
	}
	mutex_init(&ioc->base_cmds.mutex);
	ioc->base_cmds.reply = kzalloc(ioc->reply_sz, GFP_KERNEL);
	ioc->base_cmds.status = MPT3_CMD_NOT_USED; 
	ioc->port_enable_cmds.reply = kzalloc(ioc->reply_sz, GFP_KERNEL);
	ioc->port_enable_cmds.status = MPT3_CMD_NOT_USED;
	ioc->transport_cmds.reply = kzalloc(ioc->reply_sz, GFP_KERNEL);
	ioc->transport_cmds.status = MPT3_CMD_NOT_USED;
	mutex_init(&ioc->transport_cmds.mutex);
	ioc->scsih_cmds.reply = kzalloc(ioc->reply_sz, GFP_KERNEL);
	ioc->scsih_cmds.status = MPT3_CMD_NOT_USED;
	mutex_init(&ioc->scsih_cmds.mutex);
	ioc->tm_cmds.reply = kzalloc(ioc->reply_sz, GFP_KERNEL);
	ioc->tm_cmds.status = MPT3_CMD_NOT_USED;
	mutex_init(&ioc->tm_cmds.mutex);
	ioc->config_cmds.reply = kzalloc(ioc->reply_sz, GFP_KERNEL);
	ioc->config_cmds.status = MPT3_CMD_NOT_USED;
	mutex_init(&ioc->config_cmds.mutex);
	ioc->ctl_cmds.reply = kzalloc(ioc->reply_sz, GFP_KERNEL);
	ioc->ctl_cmds.sense = kzalloc(SCSI_SENSE_BUFFERSIZE, GFP_KERNEL);
	ioc->ctl_cmds.status = MPT3_CMD_NOT_USED;
	mutex_init(&ioc->ctl_cmds.mutex);
	if (!ioc->base_cmds.reply || !ioc->port_enable_cmds.reply ||
	    !ioc->transport_cmds.reply || !ioc->scsih_cmds.reply ||
	    !ioc->tm_cmds.reply || !ioc->config_cmds.reply ||
	    !ioc->ctl_cmds.reply || !ioc->ctl_cmds.sense) {
		r = -ENOMEM;
		goto out_free_resources;
	}
	for (i = 0; i < MPI2_EVENT_NOTIFY_EVENTMASK_WORDS; i++)
		ioc->event_masks[i] = -1;
	_base_unmask_events(ioc, MPI2_EVENT_SAS_DISCOVERY);
	_base_unmask_events(ioc, MPI2_EVENT_SAS_BROADCAST_PRIMITIVE);
	_base_unmask_events(ioc, MPI2_EVENT_SAS_TOPOLOGY_CHANGE_LIST);
	_base_unmask_events(ioc, MPI2_EVENT_SAS_DEVICE_STATUS_CHANGE);
								_base_unmask_events(ioc, MPI2_EVENT_ACTIVE_CABLE_EXCEPTION);
	_base_unmask_events(ioc, MPI2_EVENT_SAS_DEVICE_DISCOVERY_ERROR);
	r = _base_make_ioc_operational(ioc);
	if (r) {
		pr_alert("%s _base_make_ioc_operational gg\n", __func__);
		goto out_free_resources;
	}
				return 0;
out_free_resources:
	ioc->remove_host = 1;
	mpt3sas_base_free_resources(ioc);
	_base_release_memory_pools(ioc);
	pci_set_drvdata(ioc->pdev, NULL);
	kfree(ioc->cpu_msix_table);
			kfree(ioc->pd_handles);
	kfree(ioc->blocking_handles);
	kfree(ioc->device_remove_in_progress);
	kfree(ioc->pend_os_device_add);
	kfree(ioc->tm_cmds.reply);
	kfree(ioc->transport_cmds.reply);
	kfree(ioc->scsih_cmds.reply);
	kfree(ioc->config_cmds.reply);
	kfree(ioc->base_cmds.reply);
	kfree(ioc->port_enable_cmds.reply);
	kfree(ioc->ctl_cmds.reply);
	kfree(ioc->ctl_cmds.sense);
		ioc->ctl_cmds.reply = NULL;
	ioc->base_cmds.reply = NULL;
	ioc->tm_cmds.reply = NULL;
	ioc->scsih_cmds.reply = NULL;
	ioc->transport_cmds.reply = NULL;
	ioc->config_cmds.reply = NULL;
		return r;
}
void
mpt3sas_base_detach(struct MPT3SAS_ADAPTER *ioc)
{
		mpt3sas_base_free_resources(ioc);
	_base_release_memory_pools(ioc);
		pci_set_drvdata(ioc->pdev, NULL);
	kfree(ioc->cpu_msix_table);
			kfree(ioc->pd_handles);
	kfree(ioc->blocking_handles);
	kfree(ioc->device_remove_in_progress);
	kfree(ioc->pend_os_device_add);
		kfree(ioc->ctl_cmds.reply);
	kfree(ioc->ctl_cmds.sense);
	kfree(ioc->base_cmds.reply);
	kfree(ioc->port_enable_cmds.reply);
	kfree(ioc->tm_cmds.reply);
	kfree(ioc->transport_cmds.reply);
	kfree(ioc->scsih_cmds.reply);
	kfree(ioc->config_cmds.reply);
}
