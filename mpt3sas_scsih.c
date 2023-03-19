#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/blkdev.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/aer.h>
#include <linux/raid_class.h>
#include <linux/blk-mq-pci.h>
#include <asm/unaligned.h>
#include "mpt3sas_base.h"
static void _firmware_event_work(struct work_struct *work);
static void _scsih_remove_device(struct MPT3SAS_ADAPTER *ioc,
	struct _sas_device *sas_device);
static int _scsih_add_device(struct MPT3SAS_ADAPTER *ioc, u16 handle,
	u8 retry_count, u8 is_pd);
static void _scsih_complete_devices_scanning(struct MPT3SAS_ADAPTER *ioc);
LIST_HEAD(mpt3sas_ioc_list);
DEFINE_SPINLOCK(gioc_lock);
MODULE_AUTHOR(MPT3SAS_AUTHOR);
MODULE_DESCRIPTION(MPT3SAS_DESCRIPTION);
MODULE_LICENSE("GPL");
MODULE_VERSION(MPT3SAS_DRIVER_VERSION);
MODULE_ALIAS("mpt2sas");
static u8 scsi_io_cb_idx = -1;
static u8 base_cb_idx = -1;
static u8 port_enable_cb_idx = -1;
static u8 config_cb_idx = -1;
static int mpt3_ids;
#define MPT3SAS_MAX_LUN (16895)
static u64 max_lun = MPT3SAS_MAX_LUN;
static int host_tagset_enable = 1;
module_param(host_tagset_enable, int, 0444);
MODULE_PARM_DESC(host_tagset_enable,
	"Shared host tagset enable/disable Default: enable(1)");
struct sense_info {
	u8 skey;
	u8 asc;
	u8 ascq;
};
#define MPT3SAS_PROCESS_TRIGGER_DIAG (0xFFFB)
#define MPT3SAS_TURN_ON_PFA_LED (0xFFFC)
#define MPT3SAS_PORT_ENABLE_COMPLETE (0xFFFD)
#define MPT3SAS_ABRT_TASK_SET (0xFFFE)
#define MPT3SAS_REMOVE_UNRESPONDING_DEVICES (0xFFFF)
struct fw_event_work {
	struct list_head	list;
	struct work_struct	work;
	struct MPT3SAS_ADAPTER *ioc;
	u16			device_handle;
	u8			VF_ID;
	u8			VP_ID;
	u8			ignore;
	u16			event;
	struct kref		refcount;
	char			event_data[] __aligned(4);
};
static void fw_event_work_free(struct kref *r)
{
	kfree(container_of(r, struct fw_event_work, refcount));
}
static void fw_event_work_get(struct fw_event_work *fw_work)
{
	kref_get(&fw_work->refcount);
}
static void fw_event_work_put(struct fw_event_work *fw_work)
{
	kref_put(&fw_work->refcount, fw_event_work_free);
}
static struct fw_event_work *alloc_fw_event_work(int len)
{
	struct fw_event_work *fw_event;
	fw_event = kzalloc(sizeof(*fw_event) + len, GFP_ATOMIC);
	if (!fw_event)
		return NULL;
	kref_init(&fw_event->refcount);
	return fw_event;
}
struct hba_port *
mpt3sas_get_port_by_id(struct MPT3SAS_ADAPTER *ioc,
	u8 port_id, u8 bypass_dirty_port_flag)
{
	struct hba_port *port, *port_next;
	if (!ioc->multipath_on_hba)
		port_id = MULTIPATH_DISABLED_PORT_ID;
	list_for_each_entry_safe(port, port_next,
	    &ioc->port_table_list, list) {
		if (port->port_id != port_id)
			continue;
		if (bypass_dirty_port_flag)
			return port;
		if (port->flags & HBA_PORT_FLAG_DIRTY_PORT)
			continue;
		return port;
	}
	if (!ioc->multipath_on_hba) {
		port = kzalloc(sizeof(struct hba_port), GFP_ATOMIC);
		if (!port)
			return NULL;
		port->port_id = port_id;
		ioc_info(ioc,
		   "hba_port entry: %p, port: %d is added to hba_port list\n",
		   port, port->port_id);
		list_add_tail(&port->list,
		    &ioc->port_table_list);
		return port;
	}
	return NULL;
}
struct virtual_phy *
mpt3sas_get_vphy_by_phy(struct MPT3SAS_ADAPTER *ioc,
	struct hba_port *port, u32 phy)
{
	struct virtual_phy *vphy, *vphy_next;
	if (!port->vphys_mask)
		return NULL;
	list_for_each_entry_safe(vphy, vphy_next, &port->vphys_list, list) {
		if (vphy->phy_mask & (1 << phy))
			return vphy;
	}
	return NULL;
}
static int
_scsih_get_sas_address(struct MPT3SAS_ADAPTER *ioc, u16 handle,
	u64 *sas_address)
{
	Mpi2SasDevicePage0_t sas_device_pg0;
	Mpi2ConfigReply_t mpi_reply;
	u32 ioc_status;
	*sas_address = 0;
	if ((mpt3sas_config_get_sas_device_pg0(ioc, &mpi_reply, &sas_device_pg0,
	    MPI2_SAS_DEVICE_PGAD_FORM_HANDLE, handle))) {
		ioc_err(ioc, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		return -ENXIO;
	}
	ioc_status = le16_to_cpu(mpi_reply.IOCStatus) & MPI2_IOCSTATUS_MASK;
	if (ioc_status == MPI2_IOCSTATUS_SUCCESS) {
		if ((handle <= ioc->sas_hba.num_phys) &&
		   (!(le32_to_cpu(sas_device_pg0.DeviceInfo) &
		   MPI2_SAS_DEVICE_INFO_SEP)))
			*sas_address = ioc->sas_hba.sas_address; 
		else
			*sas_address = le64_to_cpu(sas_device_pg0.SASAddress);
		return 0;
	}
	if (ioc_status == MPI2_IOCSTATUS_CONFIG_INVALID_PAGE)
		return -ENXIO;
	ioc_err(ioc, "handle(0x%04x), ioc_status(0x%04x), failure at %s:%d/%s()!\n",
		handle, ioc_status, __FILE__, __LINE__, __func__);
	return -EIO;
}
static struct _sas_device *
__mpt3sas_get_sdev_from_target(struct MPT3SAS_ADAPTER *ioc,
		struct MPT3SAS_TARGET *tgt_priv)
{
	struct _sas_device *ret;
	assert_spin_locked(&ioc->sas_device_lock);
	ret = tgt_priv->sas_dev;
	if (ret)
		sas_device_get(ret);
	return ret;
}
struct _sas_device *
__mpt3sas_get_sdev_by_rphy(struct MPT3SAS_ADAPTER *ioc,
	struct sas_rphy *rphy)
{
	struct _sas_device *sas_device;
	assert_spin_locked(&ioc->sas_device_lock);
	list_for_each_entry(sas_device, &ioc->sas_device_list, list) {
		if (sas_device->rphy != rphy)
			continue;
		sas_device_get(sas_device);
		return sas_device;
	}
	sas_device = NULL;
	list_for_each_entry(sas_device, &ioc->sas_device_init_list, list) {
		if (sas_device->rphy != rphy)
			continue;
		sas_device_get(sas_device);
		return sas_device;
	}
	return NULL;
}
struct _sas_device *
__mpt3sas_get_sdev_by_addr(struct MPT3SAS_ADAPTER *ioc,
	u64 sas_address, struct hba_port *port)
{
	struct _sas_device *sas_device;
	if (!port)
		return NULL;
	assert_spin_locked(&ioc->sas_device_lock);
	list_for_each_entry(sas_device, &ioc->sas_device_list, list) {
		if (sas_device->sas_address != sas_address)
			continue;
		if (sas_device->port != port)
			continue;
		sas_device_get(sas_device);
		return sas_device;
	}
	list_for_each_entry(sas_device, &ioc->sas_device_init_list, list) {
		if (sas_device->sas_address != sas_address)
			continue;
		if (sas_device->port != port)
			continue;
		sas_device_get(sas_device);
		return sas_device;
	}
	return NULL;
}
struct _sas_device *
mpt3sas_get_sdev_by_addr(struct MPT3SAS_ADAPTER *ioc,
	u64 sas_address, struct hba_port *port)
{
	struct _sas_device *sas_device;
	unsigned long flags;
	spin_lock_irqsave(&ioc->sas_device_lock, flags);
	sas_device = __mpt3sas_get_sdev_by_addr(ioc,
	    sas_address, port);
	spin_unlock_irqrestore(&ioc->sas_device_lock, flags);
	return sas_device;
}
static struct _sas_device *
__mpt3sas_get_sdev_by_handle(struct MPT3SAS_ADAPTER *ioc, u16 handle)
{
	struct _sas_device *sas_device;
	assert_spin_locked(&ioc->sas_device_lock);
	list_for_each_entry(sas_device, &ioc->sas_device_list, list)
		if (sas_device->handle == handle)
			goto found_device;
	list_for_each_entry(sas_device, &ioc->sas_device_init_list, list)
		if (sas_device->handle == handle)
			goto found_device;
	return NULL;
found_device:
	sas_device_get(sas_device);
	return sas_device;
}
struct _sas_device *
mpt3sas_get_sdev_by_handle(struct MPT3SAS_ADAPTER *ioc, u16 handle)
{
	struct _sas_device *sas_device;
	unsigned long flags;
	spin_lock_irqsave(&ioc->sas_device_lock, flags);
	sas_device = __mpt3sas_get_sdev_by_handle(ioc, handle);
	spin_unlock_irqrestore(&ioc->sas_device_lock, flags);
	return sas_device;
}
static void
_scsih_sas_device_remove(struct MPT3SAS_ADAPTER *ioc,
	struct _sas_device *sas_device)
{
	unsigned long flags;
	if (!sas_device)
		return;
	ioc_info(ioc, "removing handle(0x%04x), sas_addr(0x%016llx)\n",
		 sas_device->handle, (u64)sas_device->sas_address);
	spin_lock_irqsave(&ioc->sas_device_lock, flags);
	if (!list_empty(&sas_device->list)) {
		list_del_init(&sas_device->list);
		sas_device_put(sas_device);
	}
	spin_unlock_irqrestore(&ioc->sas_device_lock, flags);
}
static void
_scsih_device_remove_by_handle(struct MPT3SAS_ADAPTER *ioc, u16 handle)
{
	struct _sas_device *sas_device;
	unsigned long flags;
	if (ioc->shost_recovery)
		return;
	spin_lock_irqsave(&ioc->sas_device_lock, flags);
	sas_device = __mpt3sas_get_sdev_by_handle(ioc, handle);
	if (sas_device) {
		list_del_init(&sas_device->list);
		sas_device_put(sas_device);
	}
	spin_unlock_irqrestore(&ioc->sas_device_lock, flags);
	if (sas_device) {
		_scsih_remove_device(ioc, sas_device);
		sas_device_put(sas_device);
	}
}
void
mpt3sas_device_remove_by_sas_address(struct MPT3SAS_ADAPTER *ioc,
	u64 sas_address, struct hba_port *port)
{
	struct _sas_device *sas_device;
	unsigned long flags;
	if (ioc->shost_recovery)
		return;
	spin_lock_irqsave(&ioc->sas_device_lock, flags);
	sas_device = __mpt3sas_get_sdev_by_addr(ioc, sas_address, port);
	if (sas_device) {
		list_del_init(&sas_device->list);
		sas_device_put(sas_device);
	}
	spin_unlock_irqrestore(&ioc->sas_device_lock, flags);
	if (sas_device) {
		_scsih_remove_device(ioc, sas_device);
		sas_device_put(sas_device);
	}
}
static void
_scsih_sas_device_add(struct MPT3SAS_ADAPTER *ioc,
	struct _sas_device *sas_device)
{
	unsigned long flags;
	spin_lock_irqsave(&ioc->sas_device_lock, flags);
	sas_device_get(sas_device);
	list_add_tail(&sas_device->list, &ioc->sas_device_list);
	spin_unlock_irqrestore(&ioc->sas_device_lock, flags);
	if (ioc->hide_drives) {
		clear_bit(sas_device->handle, ioc->pend_os_device_add);
		return;
	}
	if (!mpt3sas_transport_port_add(ioc, sas_device->handle,
	     sas_device->sas_address_parent, sas_device->port)) {
		_scsih_sas_device_remove(ioc, sas_device);
	} else if (!sas_device->starget) {
		if (!ioc->is_driver_loading) {
			mpt3sas_transport_port_remove(ioc,
			    sas_device->sas_address,
			    sas_device->sas_address_parent,
			    sas_device->port);
			_scsih_sas_device_remove(ioc, sas_device);
		}
	} else
		clear_bit(sas_device->handle, ioc->pend_os_device_add);
}
static void
_scsih_sas_device_init_add(struct MPT3SAS_ADAPTER *ioc,
	struct _sas_device *sas_device)
{
	unsigned long flags;
	spin_lock_irqsave(&ioc->sas_device_lock, flags);
	sas_device_get(sas_device);
	list_add_tail(&sas_device->list, &ioc->sas_device_init_list);
	spin_unlock_irqrestore(&ioc->sas_device_lock, flags);
}
static int
_scsih_is_end_device(u32 device_info)
{
	if (device_info & MPI2_SAS_DEVICE_INFO_END_DEVICE &&
		((device_info & MPI2_SAS_DEVICE_INFO_SSP_TARGET) |
		(device_info & MPI2_SAS_DEVICE_INFO_STP_TARGET) |
		(device_info & MPI2_SAS_DEVICE_INFO_SATA_DEVICE)))
		return 1;
	else
		return 0;
}
struct scsi_cmnd *
mpt3sas_scsih_scsi_lookup_get(struct MPT3SAS_ADAPTER *ioc, u16 smid)
{
	struct scsi_cmnd *scmd = NULL;
	struct scsiio_tracker *st;
	Mpi25SCSIIORequest_t *mpi_request;
	u16 tag = smid - 1;
	if (smid > 0  &&
	    smid <= ioc->scsiio_depth - INTERNAL_SCSIIO_CMDS_COUNT) {
		u32 unique_tag =
		    ioc->io_queue_num[tag] << BLK_MQ_UNIQUE_TAG_BITS | tag;
		mpi_request = mpt3sas_base_get_msg_frame(ioc, smid);
		if (!mpi_request->DevHandle)
			return scmd;
		scmd = scsi_host_find_tag(ioc->shost, unique_tag);
		if (scmd) {
			st = scsi_cmd_priv(scmd);
			if (st->cb_idx == 0xFF || st->smid == 0)
				scmd = NULL;
		}
	}
	return scmd;
}
static int
scsih_change_queue_depth(struct scsi_device *sdev, int qdepth)
{
	struct Scsi_Host *shost = sdev->host;
	int max_depth;
	struct MPT3SAS_ADAPTER *ioc = shost_priv(shost);
	struct MPT3SAS_DEVICE *sas_device_priv_data;
	struct MPT3SAS_TARGET *sas_target_priv_data;
	struct _sas_device *sas_device;
	unsigned long flags;
	max_depth = shost->can_queue;
	if (ioc->enable_sdev_max_qd || ioc->is_gen35_ioc)
		goto not_sata;
	sas_device_priv_data = sdev->hostdata;
	if (!sas_device_priv_data)
		goto not_sata;
	sas_target_priv_data = sas_device_priv_data->sas_target;
	if (!sas_target_priv_data)
		goto not_sata;
	spin_lock_irqsave(&ioc->sas_device_lock, flags);
	sas_device = __mpt3sas_get_sdev_from_target(ioc, sas_target_priv_data);
	if (sas_device) {
		if (sas_device->device_info & MPI2_SAS_DEVICE_INFO_SATA_DEVICE)
			max_depth = MPT3SAS_SATA_QUEUE_DEPTH;
		sas_device_put(sas_device);
	}
	spin_unlock_irqrestore(&ioc->sas_device_lock, flags);
not_sata:
	if (!sdev->tagged_supported)
		max_depth = 1;
	if (qdepth > max_depth)
		qdepth = max_depth;
	scsi_change_queue_depth(sdev, qdepth);
	sdev_printk(KERN_INFO, sdev,
	    "qdepth(%d), tagged(%d), scsi_level(%d), cmd_que(%d)\n",
	    sdev->queue_depth, sdev->tagged_supported,
	    sdev->scsi_level, ((sdev->inquiry[7] & 2) >> 1));
	return sdev->queue_depth;
}
void
mpt3sas_scsih_change_queue_depth(struct scsi_device *sdev, int qdepth)
{
	struct Scsi_Host *shost = sdev->host;
	struct MPT3SAS_ADAPTER *ioc = shost_priv(shost);
	if (ioc->enable_sdev_max_qd)
		qdepth = shost->can_queue;
	scsih_change_queue_depth(sdev, qdepth);
}
static int
scsih_target_alloc(struct scsi_target *starget)
{
	struct Scsi_Host *shost = dev_to_shost(&starget->dev);
	struct MPT3SAS_ADAPTER *ioc = shost_priv(shost);
	struct MPT3SAS_TARGET *sas_target_priv_data;
	struct _sas_device *sas_device;
	unsigned long flags;
	struct sas_rphy *rphy;
	sas_target_priv_data = kzalloc(sizeof(*sas_target_priv_data),
				       GFP_KERNEL);
	if (!sas_target_priv_data)
		return -ENOMEM;
	starget->hostdata = sas_target_priv_data;
	sas_target_priv_data->starget = starget;
	sas_target_priv_data->handle = MPT3SAS_INVALID_DEVICE_HANDLE;
	spin_lock_irqsave(&ioc->sas_device_lock, flags);
	rphy = dev_to_rphy(starget->dev.parent);
	sas_device = __mpt3sas_get_sdev_by_rphy(ioc, rphy);
	if (sas_device) {
		sas_target_priv_data->handle = sas_device->handle;
		sas_target_priv_data->sas_address = sas_device->sas_address;
		sas_target_priv_data->port = sas_device->port;
		sas_target_priv_data->sas_dev = sas_device;
		sas_device->starget = starget;
		sas_device->id = starget->id;
		sas_device->channel = starget->channel;
		if (sas_device->fast_path)
			sas_target_priv_data->flags |=
					MPT_TARGET_FASTPATH_IO;
	}
	spin_unlock_irqrestore(&ioc->sas_device_lock, flags);
	return 0;
}
static void
scsih_target_destroy(struct scsi_target *starget)
{
	struct Scsi_Host *shost = dev_to_shost(&starget->dev);
	struct MPT3SAS_ADAPTER *ioc = shost_priv(shost);
	struct MPT3SAS_TARGET *sas_target_priv_data;
	struct _sas_device *sas_device;
	unsigned long flags;
	sas_target_priv_data = starget->hostdata;
	if (!sas_target_priv_data)
		return;
	spin_lock_irqsave(&ioc->sas_device_lock, flags);
	sas_device = __mpt3sas_get_sdev_from_target(ioc, sas_target_priv_data);
	if (sas_device && (sas_device->starget == starget) &&
	    (sas_device->id == starget->id) &&
	    (sas_device->channel == starget->channel))
		sas_device->starget = NULL;
	if (sas_device) {
		sas_target_priv_data->sas_dev = NULL;
		sas_device_put(sas_device);
		sas_device_put(sas_device);
	}
	spin_unlock_irqrestore(&ioc->sas_device_lock, flags);
	kfree(sas_target_priv_data);
	starget->hostdata = NULL;
}
static int
scsih_slave_alloc(struct scsi_device *sdev)
{
	struct Scsi_Host *shost;
	struct MPT3SAS_ADAPTER *ioc;
	struct MPT3SAS_TARGET *sas_target_priv_data;
	struct MPT3SAS_DEVICE *sas_device_priv_data;
	struct scsi_target *starget;
	struct _sas_device *sas_device;
	unsigned long flags;
	sas_device_priv_data = kzalloc(sizeof(*sas_device_priv_data),
				       GFP_KERNEL);
	if (!sas_device_priv_data)
		return -ENOMEM;
	sas_device_priv_data->lun = sdev->lun;
	sas_device_priv_data->flags = MPT_DEVICE_FLAGS_INIT;
	starget = scsi_target(sdev);
	sas_target_priv_data = starget->hostdata;
	sas_target_priv_data->num_luns++;
	sas_device_priv_data->sas_target = sas_target_priv_data;
	sdev->hostdata = sas_device_priv_data;
	shost = dev_to_shost(&starget->dev);
	ioc = shost_priv(shost);
		spin_lock_irqsave(&ioc->sas_device_lock, flags);
		sas_device = __mpt3sas_get_sdev_by_addr(ioc,
		    sas_target_priv_data->sas_address,
		    sas_target_priv_data->port);
		if (sas_device && (sas_device->starget == NULL)) {
			sdev_printk(KERN_INFO, sdev,
			"%s : sas_device->starget set to starget @ %d\n",
			     __func__, __LINE__);
			sas_device->starget = starget;
		}
		if (sas_device)
			sas_device_put(sas_device);
		spin_unlock_irqrestore(&ioc->sas_device_lock, flags);
	return 0;
}
static void
scsih_slave_destroy(struct scsi_device *sdev)
{
	struct MPT3SAS_TARGET *sas_target_priv_data;
	struct scsi_target *starget;
	struct Scsi_Host *shost;
	struct MPT3SAS_ADAPTER *ioc;
	struct _sas_device *sas_device;
	unsigned long flags;
	if (!sdev->hostdata)
		return;
	starget = scsi_target(sdev);
	sas_target_priv_data = starget->hostdata;
	sas_target_priv_data->num_luns--;
	shost = dev_to_shost(&starget->dev);
	ioc = shost_priv(shost);
		spin_lock_irqsave(&ioc->sas_device_lock, flags);
		sas_device = __mpt3sas_get_sdev_from_target(ioc,
				sas_target_priv_data);
		if (sas_device && !sas_target_priv_data->num_luns)
			sas_device->starget = NULL;
		if (sas_device)
			sas_device_put(sas_device);
		spin_unlock_irqrestore(&ioc->sas_device_lock, flags);
	kfree(sdev->hostdata);
	sdev->hostdata = NULL;
}
static int
scsih_slave_configure(struct scsi_device *sdev)
{
	struct Scsi_Host *shost = sdev->host;
	struct MPT3SAS_ADAPTER *ioc = shost_priv(shost);
	struct MPT3SAS_DEVICE *sas_device_priv_data;
	struct MPT3SAS_TARGET *sas_target_priv_data;
	struct _sas_device *sas_device;
	unsigned long flags;
	int qdepth;
	u8 ssp_target = 0;
	char *ds = "";
	u16 handle;
	qdepth = 1;
	sas_device_priv_data = sdev->hostdata;
	sas_device_priv_data->configured_lun = 1;
	sas_device_priv_data->flags &= ~MPT_DEVICE_FLAGS_INIT;
	sas_target_priv_data = sas_device_priv_data->sas_target;
	handle = sas_target_priv_data->handle;
	spin_lock_irqsave(&ioc->sas_device_lock, flags);
	sas_device = __mpt3sas_get_sdev_by_addr(ioc,
	   sas_device_priv_data->sas_target->sas_address,
	   sas_device_priv_data->sas_target->port);
	if (!sas_device) {
		spin_unlock_irqrestore(&ioc->sas_device_lock, flags);
		return 1;
	}
	if (sas_device->device_info & MPI2_SAS_DEVICE_INFO_SSP_TARGET) {
		qdepth = (sas_device->port_type > 1) ?
			ioc->max_wideport_qd : ioc->max_narrowport_qd;
		ssp_target = 1;
		if (sas_device->device_info &
				MPI2_SAS_DEVICE_INFO_SEP) {
			sdev_printk(KERN_WARNING, sdev,
			"set ignore_delay_remove for handle(0x%04x)\n",
			sas_device_priv_data->sas_target->handle);
			sas_device_priv_data->ignore_delay_remove = 1;
			ds = "SES";
		} else
			ds = "SSP";
	} else {
		qdepth = ioc->max_sata_qd;
		if (sas_device->device_info & MPI2_SAS_DEVICE_INFO_STP_TARGET)
			ds = "STP";
		else if (sas_device->device_info &
		    MPI2_SAS_DEVICE_INFO_SATA_DEVICE)
			ds = "SATA";
	}
	sdev_printk(KERN_INFO, sdev, "%s: handle(0x%04x), " \
	    "sas_addr(0x%016llx), phy(%d), device_name(0x%016llx)\n",
	    ds, handle, (unsigned long long)sas_device->sas_address,
	    sas_device->phy, (unsigned long long)sas_device->device_name);
	sas_device_put(sas_device);
	spin_unlock_irqrestore(&ioc->sas_device_lock, flags);
	mpt3sas_scsih_change_queue_depth(sdev, qdepth);
	if (ssp_target) {
		sas_read_port_mode_page(sdev);
	}
	return 0;
}
static void
_scsih_fw_event_add(struct MPT3SAS_ADAPTER *ioc, struct fw_event_work *fw_event)
{
	unsigned long flags;
	if (ioc->firmware_event_thread == NULL)
		return;
	spin_lock_irqsave(&ioc->fw_event_lock, flags);
	fw_event_work_get(fw_event);
	INIT_LIST_HEAD(&fw_event->list);
	list_add_tail(&fw_event->list, &ioc->fw_event_list);
	INIT_WORK(&fw_event->work, _firmware_event_work);
	fw_event_work_get(fw_event);
	queue_work(ioc->firmware_event_thread, &fw_event->work);
	spin_unlock_irqrestore(&ioc->fw_event_lock, flags);
}
static void
_scsih_fw_event_del_from_list(struct MPT3SAS_ADAPTER *ioc, struct fw_event_work
	*fw_event)
{
	unsigned long flags;
	spin_lock_irqsave(&ioc->fw_event_lock, flags);
	if (!list_empty(&fw_event->list)) {
		list_del_init(&fw_event->list);
		fw_event_work_put(fw_event);
	}
	spin_unlock_irqrestore(&ioc->fw_event_lock, flags);
}
void
mpt3sas_port_enable_complete(struct MPT3SAS_ADAPTER *ioc)
{
	struct fw_event_work *fw_event;
	fw_event = alloc_fw_event_work(0);
	if (!fw_event)
		return;
	fw_event->event = MPT3SAS_PORT_ENABLE_COMPLETE;
	fw_event->ioc = ioc;
	_scsih_fw_event_add(ioc, fw_event);
	fw_event_work_put(fw_event);
}
static struct fw_event_work *dequeue_next_fw_event(struct MPT3SAS_ADAPTER *ioc)
{
	unsigned long flags;
	struct fw_event_work *fw_event = NULL;
	spin_lock_irqsave(&ioc->fw_event_lock, flags);
	if (!list_empty(&ioc->fw_event_list)) {
		fw_event = list_first_entry(&ioc->fw_event_list,
				struct fw_event_work, list);
		list_del_init(&fw_event->list);
	}
	spin_unlock_irqrestore(&ioc->fw_event_lock, flags);
	return fw_event;
}
static void
_scsih_fw_event_cleanup_queue(struct MPT3SAS_ADAPTER *ioc)
{
	struct fw_event_work *fw_event;
	if ((list_empty(&ioc->fw_event_list) && !ioc->current_event) ||
	    !ioc->firmware_event_thread)
		return;
	if (ioc->shost_recovery && ioc->current_event)
		ioc->current_event->ignore = 1;
	ioc->fw_events_cleanup = 1;
	while ((fw_event = dequeue_next_fw_event(ioc)) ||
	     (fw_event = ioc->current_event)) {
		if (fw_event == ioc->current_event &&
		    ioc->current_event->event !=
		    MPT3SAS_REMOVE_UNRESPONDING_DEVICES) {
			ioc->current_event = NULL;
			continue;
		}
		if (fw_event->event == MPT3SAS_PORT_ENABLE_COMPLETE) {
			ioc->port_enable_cmds.status |= MPT3_CMD_RESET;
			ioc->start_scan = 0;
		}
		if (cancel_work_sync(&fw_event->work))
			fw_event_work_put(fw_event);
		fw_event_work_put(fw_event);
	}
	ioc->fw_events_cleanup = 0;
}
static void
_scsih_internal_device_unblock(struct scsi_device *sdev,
			struct MPT3SAS_DEVICE *sas_device_priv_data)
{
	int r = 0;
	sdev_printk(KERN_WARNING, sdev, "device_unblock and setting to running, "
	    "handle(0x%04x)\n", sas_device_priv_data->sas_target->handle);
	sas_device_priv_data->block = 0;
	r = scsi_internal_device_unblock_nowait(sdev, SDEV_RUNNING);
	if (r == -EINVAL) {
		sdev_printk(KERN_WARNING, sdev,
		    "device_unblock failed with return(%d) for handle(0x%04x) "
		    "performing a block followed by an unblock\n",
		    r, sas_device_priv_data->sas_target->handle);
		sas_device_priv_data->block = 1;
		r = scsi_internal_device_block_nowait(sdev);
		if (r)
			sdev_printk(KERN_WARNING, sdev, "retried device_block "
			    "failed with return(%d) for handle(0x%04x)\n",
			    r, sas_device_priv_data->sas_target->handle);
		sas_device_priv_data->block = 0;
		r = scsi_internal_device_unblock_nowait(sdev, SDEV_RUNNING);
		if (r)
			sdev_printk(KERN_WARNING, sdev, "retried device_unblock"
			    " failed with return(%d) for handle(0x%04x)\n",
			    r, sas_device_priv_data->sas_target->handle);
	}
}
static void
_scsih_ublock_io_device(struct MPT3SAS_ADAPTER *ioc,
	u64 sas_address, struct hba_port *port)
{
	struct MPT3SAS_DEVICE *sas_device_priv_data;
	struct scsi_device *sdev;
	shost_for_each_device(sdev, ioc->shost) {
		sas_device_priv_data = sdev->hostdata;
		if (!sas_device_priv_data)
			continue;
		if (sas_device_priv_data->sas_target->sas_address
		    != sas_address)
			continue;
		if (sas_device_priv_data->sas_target->port != port)
			continue;
		if (sas_device_priv_data->block)
			_scsih_internal_device_unblock(sdev,
				sas_device_priv_data);
	}
}
inline bool _scsih_allow_scmd_to_device(struct MPT3SAS_ADAPTER *ioc,
	struct scsi_cmnd *scmd)
{
	if (ioc->pci_error_recovery)
		return false;
	if (ioc->hba_mpi_version_belonged == MPI2_VERSION) {
		if (ioc->remove_host)
			return false;
		return true;
	}
	if (ioc->remove_host) {
		switch (scmd->cmnd[0]) {
		case SYNCHRONIZE_CACHE:
		case START_STOP:
			return true;
		default:
			return false;
		}
	}
	return true;
}
static void
_scsih_issue_delayed_event_ack(struct MPT3SAS_ADAPTER *ioc, u16 smid, U16 event,
				U32 event_context)
{
	Mpi2EventAckRequest_t *ack_request;
	int i = smid - ioc->internal_smid;
	unsigned long flags;
	spin_lock_irqsave(&ioc->scsi_lookup_lock, flags);
	ioc->internal_lookup[i].cb_idx = ioc->base_cb_idx;
	spin_unlock_irqrestore(&ioc->scsi_lookup_lock, flags);
	ack_request = mpt3sas_base_get_msg_frame(ioc, smid);
	memset(ack_request, 0, sizeof(Mpi2EventAckRequest_t));
	ack_request->Function = MPI2_FUNCTION_EVENT_ACK;
	ack_request->Event = event;
	ack_request->EventContext = event_context;
	ack_request->VF_ID = 0;  
	ack_request->VP_ID = 0;
	ioc->put_smid_default(ioc, smid);
}
static void
_scsih_issue_delayed_sas_io_unit_ctrl(struct MPT3SAS_ADAPTER *ioc,
					u16 smid, u16 handle)
{
	Mpi2SasIoUnitControlRequest_t *mpi_request;
	u32 ioc_state;
	int i = smid - ioc->internal_smid;
	unsigned long flags;
	if (ioc->remove_host) {
		return;
	} else if (ioc->pci_error_recovery) {
		return;
	}
	ioc_state = mpt3sas_base_get_iocstate(ioc, 1);
	if (ioc_state != MPI2_IOC_STATE_OPERATIONAL) {
		return;
	}
	spin_lock_irqsave(&ioc->scsi_lookup_lock, flags);
	ioc->internal_lookup[i].cb_idx = ioc->tm_sas_control_cb_idx;
	spin_unlock_irqrestore(&ioc->scsi_lookup_lock, flags);
	mpi_request = mpt3sas_base_get_msg_frame(ioc, smid);
	memset(mpi_request, 0, sizeof(Mpi2SasIoUnitControlRequest_t));
	mpi_request->Function = MPI2_FUNCTION_SAS_IO_UNIT_CONTROL;
	mpi_request->Operation = MPI2_SAS_OP_REMOVE_DEVICE;
	mpi_request->DevHandle = cpu_to_le16(handle);
	ioc->put_smid_default(ioc, smid);
}
u8
mpt3sas_check_for_pending_internal_cmds(struct MPT3SAS_ADAPTER *ioc, u16 smid)
{
	struct _sc_list *delayed_sc;
	struct _event_ack_list *delayed_event_ack;
	if (!list_empty(&ioc->delayed_event_ack_list)) {
		delayed_event_ack = list_entry(ioc->delayed_event_ack_list.next,
						struct _event_ack_list, list);
		_scsih_issue_delayed_event_ack(ioc, smid,
		  delayed_event_ack->Event, delayed_event_ack->EventContext);
		list_del(&delayed_event_ack->list);
		kfree(delayed_event_ack);
		return 0;
	}
	if (!list_empty(&ioc->delayed_sc_list)) {
		delayed_sc = list_entry(ioc->delayed_sc_list.next,
						struct _sc_list, list);
		_scsih_issue_delayed_sas_io_unit_ctrl(ioc, smid,
						 delayed_sc->handle);
		list_del(&delayed_sc->list);
		kfree(delayed_sc);
		return 0;
	}
	return 1;
}
static int _scsih_set_satl_pending(struct scsi_cmnd *scmd, bool pending)
{
	struct MPT3SAS_DEVICE *priv = scmd->device->hostdata;
	if (scmd->cmnd[0] != ATA_12 && scmd->cmnd[0] != ATA_16)
		return 0;
	if (pending)
		return test_and_set_bit(0, &priv->ata_command_pending);
	clear_bit(0, &priv->ata_command_pending);
	return 0;
}
static int
scsih_qcmd(struct Scsi_Host *shost, struct scsi_cmnd *scmd)
{
	struct MPT3SAS_ADAPTER *ioc = shost_priv(shost);
	struct MPT3SAS_DEVICE *sas_device_priv_data;
	struct MPT3SAS_TARGET *sas_target_priv_data;
	struct request *rq = scsi_cmd_to_rq(scmd);
	int class;
	Mpi25SCSIIORequest_t *mpi_request;
	u32 mpi_control;
	u16 smid;
	u16 handle;
		scsi_print_command(scmd);
	sas_device_priv_data = scmd->device->hostdata;
	if (!sas_device_priv_data || !sas_device_priv_data->sas_target) {
		scmd->result = DID_NO_CONNECT << 16;
		scmd->scsi_done(scmd);
		return 0;
	}
	if (!(_scsih_allow_scmd_to_device(ioc, scmd))) {
		scmd->result = DID_NO_CONNECT << 16;
		scmd->scsi_done(scmd);
		return 0;
	}
	sas_target_priv_data = sas_device_priv_data->sas_target;
	handle = sas_target_priv_data->handle;
	if (handle == MPT3SAS_INVALID_DEVICE_HANDLE) {
		scmd->result = DID_NO_CONNECT << 16;
		scmd->scsi_done(scmd);
		return 0;
	}
	if (ioc->shost_recovery || ioc->ioc_link_reset_in_progress) {
		return SCSI_MLQUEUE_HOST_BUSY;
	} else if (sas_target_priv_data->deleted) {
		scmd->result = DID_NO_CONNECT << 16;
		scmd->scsi_done(scmd);
		return 0;
	} else if (sas_target_priv_data->tm_busy ||
		   sas_device_priv_data->block) {
		return SCSI_MLQUEUE_DEVICE_BUSY;
	}
	do {
		if (test_bit(0, &sas_device_priv_data->ata_command_pending))
			return SCSI_MLQUEUE_DEVICE_BUSY;
	} while (_scsih_set_satl_pending(scmd, true));
	if (scmd->sc_data_direction == DMA_FROM_DEVICE)
		mpi_control = MPI2_SCSIIO_CONTROL_READ;
	else if (scmd->sc_data_direction == DMA_TO_DEVICE)
		mpi_control = MPI2_SCSIIO_CONTROL_WRITE;
	else
		mpi_control = MPI2_SCSIIO_CONTROL_NODATATRANSFER;
	mpi_control |= MPI2_SCSIIO_CONTROL_SIMPLEQ;
	if (sas_device_priv_data->ncq_prio_enable) {
		class = IOPRIO_PRIO_CLASS(req_get_ioprio(rq));
		if (class == IOPRIO_CLASS_RT)
			mpi_control |= 1 << MPI2_SCSIIO_CONTROL_CMDPRI_SHIFT;
	}
	smid = mpt3sas_base_get_smid_scsiio(ioc, ioc->scsi_io_cb_idx, scmd);
	if (!smid) {
		ioc_err(ioc, "%s: failed obtaining a smid\n", __func__);
		_scsih_set_satl_pending(scmd, false);
		goto out;
	}
	mpi_request = mpt3sas_base_get_msg_frame(ioc, smid);
	memset(mpi_request, 0, ioc->request_sz);
	if (scmd->cmd_len == 32)
		mpi_control |= 4 << MPI2_SCSIIO_CONTROL_ADDCDBLEN_SHIFT;
	mpi_request->Function = MPI2_FUNCTION_SCSI_IO_REQUEST;
	mpi_request->DevHandle = cpu_to_le16(handle);
	mpi_request->DataLength = cpu_to_le32(scsi_bufflen(scmd));
	mpi_request->Control = cpu_to_le32(mpi_control);
	mpi_request->IoFlags = cpu_to_le16(scmd->cmd_len);
	mpi_request->MsgFlags = MPI2_SCSIIO_MSGFLAGS_SYSTEM_SENSE_ADDR;
	mpi_request->SenseBufferLength = SCSI_SENSE_BUFFERSIZE;
	mpi_request->SenseBufferLowAddress =
	    mpt3sas_base_get_sense_buffer_dma(ioc, smid); 
	mpi_request->SGLOffset0 = offsetof(Mpi25SCSIIORequest_t, SGL) / 4;
	int_to_scsilun(sas_device_priv_data->lun, (struct scsi_lun *)
	    mpi_request->LUN);
	memcpy(mpi_request->CDB.CDB32, scmd->cmnd, scmd->cmd_len);
	if (mpi_request->DataLength) {
		if (ioc->build_sg_scmd(ioc, scmd, smid)) {
			mpt3sas_base_free_smid(ioc, smid);
			_scsih_set_satl_pending(scmd, false);
			goto out;
		}
	} else{
		ioc->build_zero_len_sge(ioc, &mpi_request->SGL);
	}
			ioc->put_smid_scsi_io(ioc, smid,
			    le16_to_cpu(mpi_request->DevHandle));
	return 0;
 out:
	return SCSI_MLQUEUE_HOST_BUSY;
}
static void
_scsih_normalize_sense(char *sense_buffer, struct sense_info *data)
{
	if ((sense_buffer[0] & 0x7F) >= 0x72) {
		data->skey = sense_buffer[1] & 0x0F;
		data->asc = sense_buffer[2];
		data->ascq = sense_buffer[3];
	} else {
		data->skey = sense_buffer[2] & 0x0F;
		data->asc = sense_buffer[12];
		data->ascq = sense_buffer[13];
	}
}
static u8
_scsih_io_done(struct MPT3SAS_ADAPTER *ioc, u16 smid, u8 msix_index, u32 reply)
{
	Mpi25SCSIIORequest_t *mpi_request;
	Mpi2SCSIIOReply_t *mpi_reply;
	struct scsi_cmnd *scmd;
	u16 ioc_status;
	u32 xfer_cnt;
	u8 scsi_state;
	u8 scsi_status;
	struct MPT3SAS_DEVICE *sas_device_priv_data;
	u32 response_code = 0;
	mpi_reply = mpt3sas_base_get_reply_virt_addr(ioc, reply);
	scmd = mpt3sas_scsih_scsi_lookup_get(ioc, smid);
	if (scmd == NULL)
		return 1;
	_scsih_set_satl_pending(scmd, false);
	mpi_request = mpt3sas_base_get_msg_frame(ioc, smid);
	if (mpi_reply == NULL) {
		scmd->result = DID_OK << 16;
		goto out;
	}
	sas_device_priv_data = scmd->device->hostdata;
	if (!sas_device_priv_data || !sas_device_priv_data->sas_target ||
	     sas_device_priv_data->sas_target->deleted) {
		scmd->result = DID_NO_CONNECT << 16;
		goto out;
	}
	ioc_status = le16_to_cpu(mpi_reply->IOCStatus);
	xfer_cnt = le32_to_cpu(mpi_reply->TransferCount);
	scsi_set_resid(scmd, scsi_bufflen(scmd) - xfer_cnt);
	ioc_status &= MPI2_IOCSTATUS_MASK;
	scsi_status = mpi_reply->SCSIStatus;
	if (ioc_status == MPI2_IOCSTATUS_SCSI_DATA_UNDERRUN && xfer_cnt == 0 &&
	    (scsi_status == MPI2_SCSI_STATUS_BUSY ||
	     scsi_status == MPI2_SCSI_STATUS_RESERVATION_CONFLICT ||
	     scsi_status == MPI2_SCSI_STATUS_TASK_SET_FULL)) {
		ioc_status = MPI2_IOCSTATUS_SUCCESS;
	}
	if (scsi_state & MPI2_SCSI_STATE_AUTOSENSE_VALID) {
		struct sense_info data;
		const void *sense_data = mpt3sas_base_get_sense_buffer(ioc,
		    smid);
		u32 sz = min_t(u32, SCSI_SENSE_BUFFERSIZE,
		    le32_to_cpu(mpi_reply->SenseCount));
		memcpy(scmd->sense_buffer, sense_data, sz);
		_scsih_normalize_sense(scmd->sense_buffer, &data);
	}
	switch (ioc_status) {
	case MPI2_IOCSTATUS_BUSY:
	case MPI2_IOCSTATUS_INSUFFICIENT_RESOURCES:
		scmd->result = SAM_STAT_BUSY;
		break;
	case MPI2_IOCSTATUS_SCSI_DEVICE_NOT_THERE:
		scmd->result = DID_NO_CONNECT << 16;
		break;
	case MPI2_IOCSTATUS_SCSI_IOC_TERMINATED:
		if (sas_device_priv_data->block) {
			scmd->result = DID_TRANSPORT_DISRUPTED << 16;
			goto out;
		}
		scmd->result = DID_SOFT_ERROR << 16;
		break;
	case MPI2_IOCSTATUS_SCSI_TASK_TERMINATED:
	case MPI2_IOCSTATUS_SCSI_EXT_TERMINATED:
		scmd->result = DID_RESET << 16;
		break;
	case MPI2_IOCSTATUS_SCSI_RESIDUAL_MISMATCH:
		if ((xfer_cnt == 0) || (scmd->underflow > xfer_cnt))
			scmd->result = DID_SOFT_ERROR << 16;
		else
			scmd->result = (DID_OK << 16) | scsi_status;
		break;
	case MPI2_IOCSTATUS_SCSI_DATA_UNDERRUN: 
		scmd->result = (DID_OK << 16) | scsi_status;
		if ((scsi_state & MPI2_SCSI_STATE_AUTOSENSE_VALID))
			break;
		if (xfer_cnt < scmd->underflow) {
			if (scsi_status == SAM_STAT_BUSY)
				scmd->result = SAM_STAT_BUSY;
			else
				scmd->result = DID_SOFT_ERROR << 16;
		} else if (scsi_state & (MPI2_SCSI_STATE_AUTOSENSE_FAILED |
		     MPI2_SCSI_STATE_NO_SCSI_STATUS))
			scmd->result = DID_SOFT_ERROR << 16;
		else if (scsi_state & MPI2_SCSI_STATE_TERMINATED)
			scmd->result = DID_RESET << 16;
		else if (!xfer_cnt && scmd->cmnd[0] == REPORT_LUNS) {
			mpi_reply->SCSIState = MPI2_SCSI_STATE_AUTOSENSE_VALID;
			mpi_reply->SCSIStatus = SAM_STAT_CHECK_CONDITION;
			scsi_build_sense(scmd, 0, ILLEGAL_REQUEST,
					 0x20, 0);
		}
		break;
	case MPI2_IOCSTATUS_SCSI_DATA_OVERRUN:
		scsi_set_resid(scmd, 0);
		fallthrough;
	case MPI2_IOCSTATUS_SCSI_RECOVERED_ERROR:
	case MPI2_IOCSTATUS_SUCCESS:
		scmd->result = (DID_OK << 16) | scsi_status;
		if (response_code ==
		    MPI2_SCSITASKMGMT_RSP_INVALID_FRAME ||
		    (scsi_state & (MPI2_SCSI_STATE_AUTOSENSE_FAILED |
		     MPI2_SCSI_STATE_NO_SCSI_STATUS)))
			scmd->result = DID_SOFT_ERROR << 16;
		else if (scsi_state & MPI2_SCSI_STATE_TERMINATED)
			scmd->result = DID_RESET << 16;
		break;
	case MPI2_IOCSTATUS_SCSI_PROTOCOL_ERROR:
	case MPI2_IOCSTATUS_INVALID_FUNCTION:
	case MPI2_IOCSTATUS_INVALID_SGL:
	case MPI2_IOCSTATUS_INTERNAL_ERROR:
	case MPI2_IOCSTATUS_INVALID_FIELD:
	case MPI2_IOCSTATUS_INVALID_STATE:
	case MPI2_IOCSTATUS_SCSI_IO_DATA_ERROR:
	case MPI2_IOCSTATUS_SCSI_TASK_MGMT_FAILED:
	case MPI2_IOCSTATUS_INSUFFICIENT_POWER:
	default:
		scmd->result = DID_SOFT_ERROR << 16;
		break;
	}
out:
	scsi_dma_unmap(scmd);
	mpt3sas_base_free_smid(ioc, smid);
	scmd->scsi_done(scmd);
	return 0;
}
static struct virtual_phy *
_scsih_alloc_vphy(struct MPT3SAS_ADAPTER *ioc, u8 port_id, u8 phy_num)
{
	struct virtual_phy *vphy;
	struct hba_port *port;
	return NULL;
	port = mpt3sas_get_port_by_id(ioc, port_id, 0);
	if (!port)
		return NULL;
	vphy = mpt3sas_get_vphy_by_phy(ioc, port, phy_num);
	if (!vphy) {
		vphy = kzalloc(sizeof(struct virtual_phy), GFP_KERNEL);
		if (!vphy)
			return NULL;
		if (!port->vphys_mask)
			INIT_LIST_HEAD(&port->vphys_list);
		port->vphys_mask |= (1 << phy_num);
		vphy->phy_mask |= (1 << phy_num);
		list_add_tail(&vphy->list, &port->vphys_list);
		ioc_info(ioc,
		    "vphy entry: %p, port id: %d, phy:%d is added to port's vphys_list\n",
		    vphy, port->port_id, phy_num);
	}
	return vphy;
}
static void
_scsih_sas_host_refresh(struct MPT3SAS_ADAPTER *ioc)
{
	u16 sz;
	u16 ioc_status;
	int i;
	Mpi2ConfigReply_t mpi_reply;
	Mpi2SasIOUnitPage0_t *sas_iounit_pg0 = NULL;
	u16 attached_handle;
	u8 link_rate, port_id;
	struct hba_port *port;
	Mpi2SasPhyPage0_t phy_pg0;
	sz = offsetof(Mpi2SasIOUnitPage0_t, PhyData) + (ioc->sas_hba.num_phys
	    * sizeof(Mpi2SasIOUnit0PhyData_t));
	sas_iounit_pg0 = kzalloc(sz, GFP_KERNEL);
	if (!sas_iounit_pg0) {
		ioc_err(ioc, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		return;
	}
	if ((mpt3sas_config_get_sas_iounit_pg0(ioc, &mpi_reply,
	    sas_iounit_pg0, sz)) != 0)
		goto out;
	ioc_status = le16_to_cpu(mpi_reply.IOCStatus) & MPI2_IOCSTATUS_MASK;
	if (ioc_status != MPI2_IOCSTATUS_SUCCESS)
		goto out;
	for (i = 0; i < ioc->sas_hba.num_phys ; i++) {
		link_rate = sas_iounit_pg0->PhyData[i].NegotiatedLinkRate >> 4;
		if (i == 0)
			ioc->sas_hba.handle = le16_to_cpu(
			    sas_iounit_pg0->PhyData[0].ControllerDevHandle);
		port_id = sas_iounit_pg0->PhyData[i].Port;
		if (!(mpt3sas_get_port_by_id(ioc, port_id, 0))) {
			port = kzalloc(sizeof(struct hba_port), GFP_KERNEL);
			if (!port)
				goto out;
			port->port_id = port_id;
			ioc_info(ioc,
			    "hba_port entry: %p, port: %d is added to hba_port list\n",
			    port, port->port_id);
			if (ioc->shost_recovery)
				port->flags = HBA_PORT_FLAG_NEW_PORT;
			list_add_tail(&port->list, &ioc->port_table_list);
		}
		if (le32_to_cpu(sas_iounit_pg0->PhyData[i].ControllerPhyDeviceInfo) &
		    MPI2_SAS_DEVICE_INFO_SEP &&
		    (link_rate >=  MPI2_SAS_NEG_LINK_RATE_1_5)) {
			if ((mpt3sas_config_get_phy_pg0(ioc, &mpi_reply,
			    &phy_pg0, i))) {
				ioc_err(ioc,
				    "failure at %s:%d/%s()!\n",
				     __FILE__, __LINE__, __func__);
				goto out;
			}
			if (!(le32_to_cpu(phy_pg0.PhyInfo) &
			    MPI2_SAS_PHYINFO_VIRTUAL_PHY))
				continue;
			if (!_scsih_alloc_vphy(ioc, port_id, i))
				goto out;
			ioc->sas_hba.phy[i].hba_vphy = 1;
		}
		ioc->sas_hba.phy[i].handle = ioc->sas_hba.handle;
		attached_handle = le16_to_cpu(sas_iounit_pg0->PhyData[i].
		    AttachedDevHandle);
		if (attached_handle && link_rate < MPI2_SAS_NEG_LINK_RATE_1_5)
			link_rate = MPI2_SAS_NEG_LINK_RATE_1_5;
		ioc->sas_hba.phy[i].port =
		    mpt3sas_get_port_by_id(ioc, port_id, 0);
		mpt3sas_transport_update_links(ioc, ioc->sas_hba.sas_address,
		    attached_handle, i, link_rate,
		    ioc->sas_hba.phy[i].port);
	}
out:
	kfree(sas_iounit_pg0);
}
static void
_scsih_sas_host_add(struct MPT3SAS_ADAPTER *ioc)
{
	int i;
	Mpi2ConfigReply_t mpi_reply;
	Mpi2SasIOUnitPage0_t *sas_iounit_pg0 = NULL;
	Mpi2SasPhyPage0_t phy_pg0;
	Mpi2SasDevicePage0_t sas_device_pg0;
	u16 ioc_status;
	u16 sz;
	u8 num_phys, port_id;
	struct hba_port *port;
	pr_err("%s\n",__func__);
	mpt3sas_config_get_number_hba_phys(ioc, &num_phys);
	if (!num_phys) {
		ioc_err(ioc, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		return;
	}
	ioc->sas_hba.phy = kcalloc(num_phys,
	    sizeof(struct _sas_phy), GFP_KERNEL);
	if (!ioc->sas_hba.phy) {
		ioc_err(ioc, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		goto out;
	}
	ioc->sas_hba.num_phys = num_phys;
	sz = offsetof(Mpi2SasIOUnitPage0_t, PhyData) + (ioc->sas_hba.num_phys *
	    sizeof(Mpi2SasIOUnit0PhyData_t));
	sas_iounit_pg0 = kzalloc(sz, GFP_KERNEL);
	if (!sas_iounit_pg0) {
		ioc_err(ioc, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		return;
	}
	if ((mpt3sas_config_get_sas_iounit_pg0(ioc, &mpi_reply,
	    sas_iounit_pg0, sz))) {
		ioc_err(ioc, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		goto out;
	}
	ioc_status = le16_to_cpu(mpi_reply.IOCStatus) &
	    MPI2_IOCSTATUS_MASK;
	if (ioc_status != MPI2_IOCSTATUS_SUCCESS) {
		ioc_err(ioc, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		goto out;
	}
	ioc->sas_hba.parent_dev = &ioc->shost->shost_gendev;
	for (i = 0; i < ioc->sas_hba.num_phys ; i++) {
		if ((mpt3sas_config_get_phy_pg0(ioc, &mpi_reply, &phy_pg0,
		    i))) {
			ioc_err(ioc, "failure at %s:%d/%s()!\n",
				__FILE__, __LINE__, __func__);
			goto out;
		}
		ioc_status = le16_to_cpu(mpi_reply.IOCStatus) &
		    MPI2_IOCSTATUS_MASK;
		if (ioc_status != MPI2_IOCSTATUS_SUCCESS) {
			ioc_err(ioc, "failure at %s:%d/%s()!\n",
				__FILE__, __LINE__, __func__);
			goto out;
		}
		if (i == 0)
			ioc->sas_hba.handle = le16_to_cpu(sas_iounit_pg0->
			    PhyData[0].ControllerDevHandle);
		port_id = sas_iounit_pg0->PhyData[i].Port;
		if (!(mpt3sas_get_port_by_id(ioc, port_id, 0))) {
			port = kzalloc(sizeof(struct hba_port), GFP_KERNEL);
			if (!port)
				goto out;
			port->port_id = port_id;
			ioc_info(ioc,
			   "hba_port entry: %p, port: %d is added to hba_port list\n",
			   port, port->port_id);
			list_add_tail(&port->list,
			    &ioc->port_table_list);
		}
		if ((le32_to_cpu(phy_pg0.PhyInfo) &
		    MPI2_SAS_PHYINFO_VIRTUAL_PHY) &&
		    (phy_pg0.NegotiatedLinkRate >> 4) >=
		    MPI2_SAS_NEG_LINK_RATE_1_5) {
			if (!_scsih_alloc_vphy(ioc, port_id, i))
				goto out;
			ioc->sas_hba.phy[i].hba_vphy = 1;
		}
		ioc->sas_hba.phy[i].handle = ioc->sas_hba.handle;
		ioc->sas_hba.phy[i].phy_id = i;
		ioc->sas_hba.phy[i].port =
		    mpt3sas_get_port_by_id(ioc, port_id, 0);
		mpt3sas_transport_add_host_phy(ioc, &ioc->sas_hba.phy[i],
		    phy_pg0, ioc->sas_hba.parent_dev);
	}
	if ((mpt3sas_config_get_sas_device_pg0(ioc, &mpi_reply, &sas_device_pg0,
	    MPI2_SAS_DEVICE_PGAD_FORM_HANDLE, ioc->sas_hba.handle))) {
		ioc_err(ioc, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		goto out;
	}
	ioc->sas_hba.sas_address = le64_to_cpu(sas_device_pg0.SASAddress);
	ioc_info(ioc, "host_add: handle(0x%04x), sas_addr(0x%016llx), phys(%d)\n",
		 ioc->sas_hba.handle,
		 (u64)ioc->sas_hba.sas_address,
		 ioc->sas_hba.num_phys);
out:
	kfree(sas_iounit_pg0);
}
static u8
_scsih_check_access_status(struct MPT3SAS_ADAPTER *ioc, u64 sas_address,
	u16 handle, u8 access_status)
{
	u8 rc = 1;
	char *desc = NULL;
	switch (access_status) {
	case MPI2_SAS_DEVICE0_ASTATUS_NO_ERRORS:
	case MPI2_SAS_DEVICE0_ASTATUS_SATA_NEEDS_INITIALIZATION:
		rc = 0;
		break;
	case MPI2_SAS_DEVICE0_ASTATUS_SATA_CAPABILITY_FAILED:
		desc = "sata capability failed";
		break;
	case MPI2_SAS_DEVICE0_ASTATUS_SATA_AFFILIATION_CONFLICT:
		desc = "sata affiliation conflict";
		break;
	case MPI2_SAS_DEVICE0_ASTATUS_ROUTE_NOT_ADDRESSABLE:
		desc = "route not addressable";
		break;
	case MPI2_SAS_DEVICE0_ASTATUS_SMP_ERROR_NOT_ADDRESSABLE:
		desc = "smp error not addressable";
		break;
	case MPI2_SAS_DEVICE0_ASTATUS_DEVICE_BLOCKED:
		desc = "device blocked";
		break;
	case MPI2_SAS_DEVICE0_ASTATUS_SATA_INIT_FAILED:
	case MPI2_SAS_DEVICE0_ASTATUS_SIF_UNKNOWN:
	case MPI2_SAS_DEVICE0_ASTATUS_SIF_AFFILIATION_CONFLICT:
	case MPI2_SAS_DEVICE0_ASTATUS_SIF_DIAG:
	case MPI2_SAS_DEVICE0_ASTATUS_SIF_IDENTIFICATION:
	case MPI2_SAS_DEVICE0_ASTATUS_SIF_CHECK_POWER:
	case MPI2_SAS_DEVICE0_ASTATUS_SIF_PIO_SN:
	case MPI2_SAS_DEVICE0_ASTATUS_SIF_MDMA_SN:
	case MPI2_SAS_DEVICE0_ASTATUS_SIF_UDMA_SN:
	case MPI2_SAS_DEVICE0_ASTATUS_SIF_ZONING_VIOLATION:
	case MPI2_SAS_DEVICE0_ASTATUS_SIF_NOT_ADDRESSABLE:
	case MPI2_SAS_DEVICE0_ASTATUS_SIF_MAX:
		desc = "sata initialization failed";
		break;
	default:
		desc = "unknown";
		break;
	}
	if (!rc)
		return 0;
	ioc_err(ioc, "discovery errors(%s): sas_address(0x%016llx), handle(0x%04x)\n",
		desc, (u64)sas_address, handle);
	return rc;
}
static void
_scsih_check_device(struct MPT3SAS_ADAPTER *ioc,
	u64 parent_sas_address, u16 handle, u8 phy_number, u8 link_rate)
{
	Mpi2ConfigReply_t mpi_reply;
	Mpi2SasDevicePage0_t sas_device_pg0;
	struct _sas_device *sas_device = NULL;
	u32 ioc_status;
	unsigned long flags;
	u64 sas_address;
	struct scsi_target *starget;
	struct MPT3SAS_TARGET *sas_target_priv_data;
	u32 device_info;
	struct hba_port *port;
	if ((mpt3sas_config_get_sas_device_pg0(ioc, &mpi_reply, &sas_device_pg0,
	    MPI2_SAS_DEVICE_PGAD_FORM_HANDLE, handle)))
		return;
	ioc_status = le16_to_cpu(mpi_reply.IOCStatus) & MPI2_IOCSTATUS_MASK;
	if (ioc_status != MPI2_IOCSTATUS_SUCCESS)
		return;
	if (phy_number != sas_device_pg0.PhyNum)
		return;
	device_info = le32_to_cpu(sas_device_pg0.DeviceInfo);
	if (!(_scsih_is_end_device(device_info)))
		return;
	spin_lock_irqsave(&ioc->sas_device_lock, flags);
	sas_address = le64_to_cpu(sas_device_pg0.SASAddress);
	port = mpt3sas_get_port_by_id(ioc, sas_device_pg0.PhysicalPort, 0);
	if (!port)
		goto out_unlock;
	sas_device = __mpt3sas_get_sdev_by_addr(ioc,
	    sas_address, port);
	if (!sas_device)
		goto out_unlock;
	if (unlikely(sas_device->handle != handle)) {
		starget = sas_device->starget;
		sas_target_priv_data = starget->hostdata;
		starget_printk(KERN_INFO, starget,
			"handle changed from(0x%04x) to (0x%04x)!!!\n",
			sas_device->handle, handle);
		sas_target_priv_data->handle = handle;
		sas_device->handle = handle;
		sas_device->is_chassis_slot_valid = 0;
	}
	if (!(le16_to_cpu(sas_device_pg0.Flags) &
	    MPI2_SAS_DEVICE0_FLAGS_DEVICE_PRESENT)) {
		ioc_err(ioc, "device is not present handle(0x%04x), flags!!!\n",
			handle);
		goto out_unlock;
	}
	if (_scsih_check_access_status(ioc, sas_address, handle,
	    sas_device_pg0.AccessStatus))
		goto out_unlock;
	spin_unlock_irqrestore(&ioc->sas_device_lock, flags);
	_scsih_ublock_io_device(ioc, sas_address, port);
	if (sas_device)
		sas_device_put(sas_device);
	return;
out_unlock:
	spin_unlock_irqrestore(&ioc->sas_device_lock, flags);
	if (sas_device)
		sas_device_put(sas_device);
}
static int
_scsih_add_device(struct MPT3SAS_ADAPTER *ioc, u16 handle, u8 phy_num,
	u8 is_pd)
{
	Mpi2ConfigReply_t mpi_reply;
	Mpi2SasDevicePage0_t sas_device_pg0;
	struct _sas_device *sas_device;
	u32 ioc_status;
	u64 sas_address;
	u32 device_info;
	u8 port_id;
	if ((mpt3sas_config_get_sas_device_pg0(ioc, &mpi_reply, &sas_device_pg0,
	    MPI2_SAS_DEVICE_PGAD_FORM_HANDLE, handle))) {
		ioc_err(ioc, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		return -1;
	}
	ioc_status = le16_to_cpu(mpi_reply.IOCStatus) &
	    MPI2_IOCSTATUS_MASK;
	if (ioc_status != MPI2_IOCSTATUS_SUCCESS) {
		ioc_err(ioc, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		return -1;
	}
	device_info = le32_to_cpu(sas_device_pg0.DeviceInfo);
	if (!(_scsih_is_end_device(device_info)))
		return -1;
	set_bit(handle, ioc->pend_os_device_add);
	sas_address = le64_to_cpu(sas_device_pg0.SASAddress);
	if (!(le16_to_cpu(sas_device_pg0.Flags) &
	    MPI2_SAS_DEVICE0_FLAGS_DEVICE_PRESENT)) {
		ioc_err(ioc, "device is not present handle(0x04%x)!!!\n",
			handle);
		return -1;
	}
	if (_scsih_check_access_status(ioc, sas_address, handle,
	    sas_device_pg0.AccessStatus))
		return -1;
	port_id = sas_device_pg0.PhysicalPort;
	sas_device = mpt3sas_get_sdev_by_addr(ioc,
	    sas_address, mpt3sas_get_port_by_id(ioc, port_id, 0)); 
	if (sas_device) { 
		clear_bit(handle, ioc->pend_os_device_add);
		sas_device_put(sas_device);
		return -1;
	}
	sas_device = kzalloc(sizeof(struct _sas_device),
	    GFP_KERNEL);
	if (!sas_device) {
		ioc_err(ioc, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		return 0;
	}
	kref_init(&sas_device->refcount);
	sas_device->handle = handle;
	if (_scsih_get_sas_address(ioc,
	    le16_to_cpu(sas_device_pg0.ParentDevHandle),
	    &sas_device->sas_address_parent) != 0)
		ioc_err(ioc, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
	sas_device->device_info = device_info;
	sas_device->sas_address = sas_address;
	sas_device->phy = sas_device_pg0.PhyNum;
	sas_device->fast_path = (le16_to_cpu(sas_device_pg0.Flags) &
	    MPI25_SAS_DEVICE0_FLAGS_FAST_PATH_CAPABLE) ? 1 : 0; 
	sas_device->port = mpt3sas_get_port_by_id(ioc, port_id, 0);
	if (!sas_device->port) {
		ioc_err(ioc, "failure at %s:%d/%s()!\n",
		    __FILE__, __LINE__, __func__);
		goto out;
	}
	sas_device->device_name = le64_to_cpu(sas_device_pg0.DeviceName);
	sas_device->port_type = sas_device_pg0.MaxPortConnections;
	ioc_info(ioc,
	    "handle(0x%0x) sas_address(0x%016llx) port_type(0x%0x)\n",
	    handle, sas_device->sas_address, sas_device->port_type);
	if (ioc->wait_for_discovery_to_complete)
		_scsih_sas_device_init_add(ioc, sas_device); 
	else
		_scsih_sas_device_add(ioc, sas_device);
out:
	sas_device_put(sas_device);
	return 0;
}
static void
_scsih_remove_device(struct MPT3SAS_ADAPTER *ioc,
	struct _sas_device *sas_device)
{
	struct MPT3SAS_TARGET *sas_target_priv_data;
	if (sas_device->starget && sas_device->starget->hostdata) {
		sas_target_priv_data = sas_device->starget->hostdata;
		sas_target_priv_data->deleted = 1;
		_scsih_ublock_io_device(ioc, sas_device->sas_address,
		    sas_device->port);
		sas_target_priv_data->handle =
		     MPT3SAS_INVALID_DEVICE_HANDLE;
	}
	if (!ioc->hide_drives)
		mpt3sas_transport_port_remove(ioc,
		    sas_device->sas_address,
		    sas_device->sas_address_parent,
		    sas_device->port);
	ioc_info(ioc, "removing handle(0x%04x), sas_addr(0x%016llx)\n",
		 sas_device->handle, (u64)sas_device->sas_address);
}
static int
_scsih_sas_topology_change_event(struct MPT3SAS_ADAPTER *ioc,
	struct fw_event_work *fw_event)
{
	int i;
	u16 parent_handle, handle;
	u16 reason_code;
	u8 phy_number, max_phys;
	u64 sas_address;
	unsigned long flags;
	u8 link_rate, prev_link_rate;
	struct hba_port *port;
	Mpi2EventDataSasTopologyChangeList_t *event_data =
		(Mpi2EventDataSasTopologyChangeList_t *)
		fw_event->event_data;
	pr_err("%s\n",__func__);
	if (ioc->shost_recovery || ioc->remove_host || ioc->pci_error_recovery)
		return 0;
	if (!ioc->sas_hba.num_phys)
		_scsih_sas_host_add(ioc);
	else
		_scsih_sas_host_refresh(ioc);
	if (fw_event->ignore) {
		return 0;
	}
	parent_handle = le16_to_cpu(event_data->ExpanderDevHandle);
	port = mpt3sas_get_port_by_id(ioc, event_data->PhysicalPort, 0);
	spin_lock_irqsave(&ioc->sas_node_lock, flags);
	if (parent_handle < ioc->sas_hba.num_phys) {
		sas_address = ioc->sas_hba.sas_address;
		max_phys = ioc->sas_hba.num_phys;
	} else {
		spin_unlock_irqrestore(&ioc->sas_node_lock, flags);
		return 0;
	}
	spin_unlock_irqrestore(&ioc->sas_node_lock, flags);
	for (i = 0; i < event_data->NumEntries; i++) {
		if (fw_event->ignore) {
			return 0;
		}
		if (ioc->remove_host || ioc->pci_error_recovery)
			return 0;
		phy_number = event_data->StartPhyNum + i;
		if (phy_number >= max_phys)
			continue;
		reason_code = event_data->PHY[i].PhyStatus &
		    MPI2_EVENT_SAS_TOPO_RC_MASK;
		if ((event_data->PHY[i].PhyStatus &
		    MPI2_EVENT_SAS_TOPO_PHYSTATUS_VACANT) && (reason_code !=
		    MPI2_EVENT_SAS_TOPO_RC_TARG_NOT_RESPONDING))
				continue;
		handle = le16_to_cpu(event_data->PHY[i].AttachedDevHandle);
		if (!handle)
			continue;
		link_rate = event_data->PHY[i].LinkRate >> 4;
		prev_link_rate = event_data->PHY[i].LinkRate & 0xF;
		switch (reason_code) {
		case MPI2_EVENT_SAS_TOPO_RC_PHY_CHANGED:
			if (ioc->shost_recovery)
				break;
			if (link_rate == prev_link_rate)
				break;
			mpt3sas_transport_update_links(ioc, sas_address,
			    handle, phy_number, link_rate, port);
			if (link_rate < MPI2_SAS_NEG_LINK_RATE_1_5)
				break;
			_scsih_check_device(ioc, sas_address, handle,
			    phy_number, link_rate);
			if (!test_bit(handle, ioc->pend_os_device_add))
				break;
			fallthrough;
		case MPI2_EVENT_SAS_TOPO_RC_TARG_ADDED:
			if (ioc->shost_recovery)
				break;
			mpt3sas_transport_update_links(ioc, sas_address,
			    handle, phy_number, link_rate, port);
			_scsih_add_device(ioc, handle, phy_number, 0);
			break;
		case MPI2_EVENT_SAS_TOPO_RC_TARG_NOT_RESPONDING:
			_scsih_device_remove_by_handle(ioc, handle);
			break;
		}
	}
	return 0;
}
static void
_scsih_sas_device_status_change_event(struct MPT3SAS_ADAPTER *ioc,
	Mpi2EventDataSasDeviceStatusChange_t *event_data)
{
	struct MPT3SAS_TARGET *target_priv_data;
	struct _sas_device *sas_device;
	u64 sas_address;
	unsigned long flags;
	if ((ioc->facts.HeaderVersion >> 8) < 0xC)
		return;
	if (event_data->ReasonCode !=
	    MPI2_EVENT_SAS_DEV_STAT_RC_INTERNAL_DEVICE_RESET &&
	   event_data->ReasonCode !=
	    MPI2_EVENT_SAS_DEV_STAT_RC_CMP_INTERNAL_DEV_RESET)
		return;
	spin_lock_irqsave(&ioc->sas_device_lock, flags);
	sas_address = le64_to_cpu(event_data->SASAddress);
	sas_device = __mpt3sas_get_sdev_by_addr(ioc,
	    sas_address,
	    mpt3sas_get_port_by_id(ioc, event_data->PhysicalPort, 0));
	if (!sas_device || !sas_device->starget)
		goto out;
	target_priv_data = sas_device->starget->hostdata;
	if (!target_priv_data)
		goto out;
	if (event_data->ReasonCode ==
	    MPI2_EVENT_SAS_DEV_STAT_RC_INTERNAL_DEVICE_RESET)
		target_priv_data->tm_busy = 1;
	else
		target_priv_data->tm_busy = 0;
out:
	if (sas_device)
		sas_device_put(sas_device);
	spin_unlock_irqrestore(&ioc->sas_device_lock, flags);
}
static void
_scsih_sas_discovery_event(struct MPT3SAS_ADAPTER *ioc,
	struct fw_event_work *fw_event)
{
	Mpi2EventDataSasDiscovery_t *event_data =
		(Mpi2EventDataSasDiscovery_t *) fw_event->event_data;
	pr_err("%s: %s\n",__func__,event_data->ReasonCode == MPI2_EVENT_SAS_DISC_RC_STARTED?"started":"completed");
	if (event_data->ReasonCode == MPI2_EVENT_SAS_DISC_RC_STARTED &&
	    !ioc->sas_hba.num_phys) {
		_scsih_sas_host_add(ioc);
	}
}
static void
_mpt3sas_fw_work(struct MPT3SAS_ADAPTER *ioc, struct fw_event_work *fw_event)
{
	ioc->current_event = fw_event;
	_scsih_fw_event_del_from_list(ioc, fw_event);
	if (ioc->remove_host || ioc->pci_error_recovery) {
		fw_event_work_put(fw_event);
		ioc->current_event = NULL;
		return;
	}
	switch (fw_event->event) {
	case MPT3SAS_REMOVE_UNRESPONDING_DEVICES:
		pr_alert("%s 淦 MPT3SAS_REMOVE_UNRESPONDING_DEVICES\n", __func__);
		break;
	case MPT3SAS_PORT_ENABLE_COMPLETE:
		ioc->start_scan = 0;
		break;
	case MPI2_EVENT_SAS_TOPOLOGY_CHANGE_LIST:
		_scsih_sas_topology_change_event(ioc, fw_event);
		break;
	case MPI2_EVENT_SAS_DISCOVERY:
		_scsih_sas_discovery_event(ioc, fw_event);
		break;
	}
	fw_event_work_put(fw_event);
	ioc->current_event = NULL;
}
static void
_firmware_event_work(struct work_struct *work)
{
	struct fw_event_work *fw_event = container_of(work,
	    struct fw_event_work, work);
	_mpt3sas_fw_work(fw_event->ioc, fw_event);
}
u8
mpt3sas_scsih_event_callback(struct MPT3SAS_ADAPTER *ioc, u8 msix_index,
	u32 reply)
{
	struct fw_event_work *fw_event;
	Mpi2EventNotificationReply_t *mpi_reply;
	u16 event;
	u16 sz;
	pr_err("%s\n",__func__);
	if (ioc->pci_error_recovery)
		return 1;
	mpi_reply = mpt3sas_base_get_reply_virt_addr(ioc, reply);
	if (unlikely(!mpi_reply)) {
		ioc_err(ioc, "mpi_reply not valid at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		return 1;
	}
	event = le16_to_cpu(mpi_reply->Event);
	switch (event) {
	case MPI2_EVENT_SAS_TOPOLOGY_CHANGE_LIST:
		break;
	case MPI2_EVENT_SAS_DEVICE_STATUS_CHANGE:
		_scsih_sas_device_status_change_event(ioc,
		    (Mpi2EventDataSasDeviceStatusChange_t *)
		    mpi_reply->EventData);
		break;
	case MPI2_EVENT_SAS_DISCOVERY:
	case MPI2_EVENT_SAS_DEVICE_DISCOVERY_ERROR:
		break;
	default: 
		return 1;
	}
	sz = le16_to_cpu(mpi_reply->EventDataLength) * 4;
	fw_event = alloc_fw_event_work(sz);
	if (!fw_event) {
		ioc_err(ioc, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		return 1;
	}
	memcpy(fw_event->event_data, mpi_reply->EventData, sz);
	fw_event->ioc = ioc;
	fw_event->VF_ID = mpi_reply->VF_ID;
	fw_event->VP_ID = mpi_reply->VP_ID;
	fw_event->event = event;
	_scsih_fw_event_add(ioc, fw_event);
	fw_event_work_put(fw_event);
	return 1;
}
static int
_scsih_get_shost_and_ioc(struct pci_dev *pdev,
	struct Scsi_Host **shost, struct MPT3SAS_ADAPTER **ioc)
{
	*shost = pci_get_drvdata(pdev);
	if (*shost == NULL) {
		dev_err(&pdev->dev, "pdev's driver data is null\n");
		return -ENXIO;
	}
	*ioc = shost_priv(*shost);
	if (*ioc == NULL) {
		dev_err(&pdev->dev, "shost's private data is null\n");
		return -ENXIO;
	}
	return 0;
}
static void scsih_remove(struct pci_dev *pdev)
{
	struct Scsi_Host *shost;
	struct MPT3SAS_ADAPTER *ioc;
	struct workqueue_struct	*wq;
	unsigned long flags;
	struct hba_port *port, *port_next;
	if (_scsih_get_shost_and_ioc(pdev, &shost, &ioc))
		return;
	ioc->remove_host = 1;
	_scsih_fw_event_cleanup_queue(ioc);
	spin_lock_irqsave(&ioc->fw_event_lock, flags);
	wq = ioc->firmware_event_thread;
	ioc->firmware_event_thread = NULL;
	spin_unlock_irqrestore(&ioc->fw_event_lock, flags);
	if (wq)
		destroy_workqueue(wq);
	sas_remove_host(shost);
	list_for_each_entry_safe(port, port_next,
	    &ioc->port_table_list, list) {
		list_del(&port->list);
		kfree(port);
	}
	if (ioc->sas_hba.num_phys) {
		kfree(ioc->sas_hba.phy);
		ioc->sas_hba.phy = NULL;
		ioc->sas_hba.num_phys = 0;
	}
	mpt3sas_base_detach(ioc);
	spin_lock(&gioc_lock);
	list_del(&ioc->list);
	spin_unlock(&gioc_lock);
	scsi_host_put(shost);
}
static struct _sas_device *get_next_sas_device(struct MPT3SAS_ADAPTER *ioc)
{
	struct _sas_device *sas_device = NULL;
	unsigned long flags;
	spin_lock_irqsave(&ioc->sas_device_lock, flags);
	if (!list_empty(&ioc->sas_device_init_list)) {
		sas_device = list_first_entry(&ioc->sas_device_init_list,
				struct _sas_device, list);
		sas_device_get(sas_device);
	}
	spin_unlock_irqrestore(&ioc->sas_device_lock, flags);
	return sas_device;
}
static void sas_device_make_active(struct MPT3SAS_ADAPTER *ioc,
		struct _sas_device *sas_device)
{
	unsigned long flags;
	spin_lock_irqsave(&ioc->sas_device_lock, flags);
	if (!list_empty(&sas_device->list)) {
		list_del_init(&sas_device->list);
		sas_device_put(sas_device);
	}
	sas_device_get(sas_device);
	list_add_tail(&sas_device->list, &ioc->sas_device_list);
	spin_unlock_irqrestore(&ioc->sas_device_lock, flags);
}
static void
_scsih_probe_sas(struct MPT3SAS_ADAPTER *ioc)
{
	struct _sas_device *sas_device;
	while ((sas_device = get_next_sas_device(ioc))) {
		if (!mpt3sas_transport_port_add(ioc, sas_device->handle,
		    sas_device->sas_address_parent, sas_device->port)) { 
			_scsih_sas_device_remove(ioc, sas_device);
			sas_device_put(sas_device);
			continue;
		} else if (!sas_device->starget) {
			if (!ioc->is_driver_loading) {
				mpt3sas_transport_port_remove(ioc,
				    sas_device->sas_address,
				    sas_device->sas_address_parent,
				    sas_device->port);
				_scsih_sas_device_remove(ioc, sas_device);
				sas_device_put(sas_device);
				continue;
			}
		}
		sas_device_make_active(ioc, sas_device); 
		sas_device_put(sas_device);
	}
}
static void
_scsih_probe_devices(struct MPT3SAS_ADAPTER *ioc)
{
	if (!(ioc->facts.ProtocolFlags & MPI2_IOCFACTS_PROTOCOL_SCSI_INITIATOR))
		return;  
		_scsih_probe_sas(ioc); 
}
static void
scsih_scan_start(struct Scsi_Host *shost)
{
	struct MPT3SAS_ADAPTER *ioc = shost_priv(shost);
	int rc;
	ioc->start_scan = 1;
	rc = mpt3sas_port_enable(ioc);
	if (rc != 0)
		ioc_info(ioc, "port enable: FAILED\n");
}
static void _scsih_complete_devices_scanning(struct MPT3SAS_ADAPTER *ioc)
{
	if (ioc->wait_for_discovery_to_complete) {
		ioc->wait_for_discovery_to_complete = 0;
		_scsih_probe_devices(ioc);
	}
	ioc->is_driver_loading = 0;
}
static int
scsih_scan_finished(struct Scsi_Host *shost, unsigned long time)
{
	struct MPT3SAS_ADAPTER *ioc = shost_priv(shost);
	u32 ioc_state;
	if (time >= (300 * HZ)) { 
		ioc->port_enable_cmds.status = MPT3_CMD_NOT_USED;
		ioc_info(ioc, "port enable: FAILED with timeout (timeout=300s)\n");
		ioc->is_driver_loading = 0;
		return 1;
	}
	if (ioc->start_scan) { 
		ioc_state = mpt3sas_base_get_iocstate(ioc, 0);
		if ((ioc_state & MPI2_IOC_STATE_MASK) == MPI2_IOC_STATE_FAULT) {
			pr_alert("%s ioc_state is MPI2_IOC_STATE_FAULT\n", __func__);
			goto out;
		} else if ((ioc_state & MPI2_IOC_STATE_MASK) ==
				MPI2_IOC_STATE_COREDUMP) {
			pr_alert("%s ioc_state is MPI2_IOC_STATE_COREDUMP\n", __func__);
			goto out;
		}
		return 0; 
	}
	if (ioc->port_enable_cmds.status & MPT3_CMD_RESET) { 
		ioc_info(ioc,
		    "port enable: aborted due to diag reset\n");
		ioc->port_enable_cmds.status = MPT3_CMD_NOT_USED;
		goto out;
	}
	if (ioc->start_scan_failed) { 
		ioc_info(ioc, "port enable: FAILED with (ioc_status=0x%08x)\n",
			 ioc->start_scan_failed);
		ioc->is_driver_loading = 0;
		ioc->wait_for_discovery_to_complete = 0;
		ioc->remove_host = 1;
		return 1;
	}
	ioc_info(ioc, "port enable: SUCCESS\n");
	ioc->port_enable_cmds.status = MPT3_CMD_NOT_USED; 
	_scsih_complete_devices_scanning(ioc);
out:
	return 1;
}
static struct scsi_host_template mpt3sas_driver_template = {
	.module				= THIS_MODULE,
	.name				= "Fusion MPT SAS Host",
	.proc_name			= MPT3SAS_DRIVER_NAME,
	.queuecommand			= scsih_qcmd,
	.target_alloc			= scsih_target_alloc,
	.slave_alloc			= scsih_slave_alloc,
	.slave_configure		= scsih_slave_configure,
	.target_destroy			= scsih_target_destroy,
	.slave_destroy			= scsih_slave_destroy,
	.scan_finished			= scsih_scan_finished,
	.scan_start			= scsih_scan_start,
	.change_queue_depth		= scsih_change_queue_depth,
	.can_queue			= 1,
	.this_id			= -1,
	.sg_tablesize			= MPT3SAS_SG_DEPTH,
	.max_sectors			= 32767,
	.max_segment_size		= 0xffffffff,
	.cmd_per_lun			= 7,
	.track_queue_depth		= 1,
	.cmd_size			= sizeof(struct scsiio_tracker),
};
static u16
_scsih_determine_hba_mpi_version(struct pci_dev *pdev)
{
	switch (pdev->device) {
	case MPI25_MFGPAGE_DEVID_SAS3008:
	case MPI26_MFGPAGE_DEVID_SAS3408:
	case MPI26_MFGPAGE_DEVID_SAS3416:
		return MPI26_VERSION;
	}
	return 0;
}
static int
_scsih_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct MPT3SAS_ADAPTER *ioc;
	struct Scsi_Host *shost = NULL;
	int rv;
	u16 hba_mpi_version;
	int iopoll_q_count = 0;
	hba_mpi_version = _scsih_determine_hba_mpi_version(pdev); 
	if (hba_mpi_version == 0)
		return -ENODEV;
		shost = scsi_host_alloc(&mpt3sas_driver_template,
		  sizeof(struct MPT3SAS_ADAPTER));
		if (!shost)
			return -ENODEV;
		ioc = shost_priv(shost);
		memset(ioc, 0, sizeof(struct MPT3SAS_ADAPTER));
		ioc->hba_mpi_version_belonged = hba_mpi_version;
		ioc->id = mpt3_ids++;
		sprintf(ioc->driver_name, "%s", MPT3SAS_DRIVER_NAME);
		switch (pdev->device) {
		case MPI26_MFGPAGE_DEVID_SAS3408:
		case MPI26_MFGPAGE_DEVID_SAS3416:
			ioc->is_gen35_ioc = 1;
			break;
		default: 
			ioc->is_gen35_ioc = ioc->is_aero_ioc = 0;
		}
			if (ioc->is_gen35_ioc)
				ioc->combined_reply_index_count =
				 MPT3_SUP_REPLY_POST_HOST_INDEX_REG_COUNT_G35;
				ioc->multipath_on_hba = 0;
	INIT_LIST_HEAD(&ioc->list);
	spin_lock(&gioc_lock);
	list_add_tail(&ioc->list, &mpt3sas_ioc_list);
	spin_unlock(&gioc_lock);
	ioc->shost = shost;
	ioc->pdev = pdev;
	ioc->scsi_io_cb_idx = scsi_io_cb_idx;
	ioc->base_cb_idx = base_cb_idx;
	ioc->port_enable_cb_idx = port_enable_cb_idx;
	ioc->config_cb_idx = config_cb_idx;
	mutex_init(&ioc->pci_access_mutex);
	spin_lock_init(&ioc->ioc_reset_in_progress_lock);
	spin_lock_init(&ioc->scsi_lookup_lock);
	spin_lock_init(&ioc->sas_device_lock);
	spin_lock_init(&ioc->sas_node_lock);
	spin_lock_init(&ioc->fw_event_lock);
	INIT_LIST_HEAD(&ioc->sas_device_list);
	INIT_LIST_HEAD(&ioc->sas_device_init_list);
	INIT_LIST_HEAD(&ioc->fw_event_list);
	INIT_LIST_HEAD(&ioc->sas_hba.sas_port_list);
	INIT_LIST_HEAD(&ioc->delayed_sc_list);
	INIT_LIST_HEAD(&ioc->delayed_event_ack_list);
	INIT_LIST_HEAD(&ioc->reply_queue_list);
	INIT_LIST_HEAD(&ioc->port_table_list);
	sprintf(ioc->name, "%s_cm%d", ioc->driver_name, ioc->id);
	shost->max_cmd_len = 32;
	shost->max_lun = max_lun; 
	shost->transportt = mpt3sas_transport_template;
	shost->unique_id = ioc->id; 
	snprintf(ioc->firmware_event_name, sizeof(ioc->firmware_event_name),
	    "fw_event_%s%d", ioc->driver_name, ioc->id);
	ioc->firmware_event_thread = alloc_ordered_workqueue(
	    ioc->firmware_event_name, 0);
	if (!ioc->firmware_event_thread) {
		ioc_err(ioc, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		rv = -ENODEV;
		goto out_thread_fail;
	}
	shost->host_tagset = 0;
	if (ioc->is_gen35_ioc && host_tagset_enable) 
		shost->host_tagset = 1;
	ioc->is_driver_loading = 1; 
	if ((mpt3sas_base_attach(ioc))) {
		ioc_err(ioc, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		rv = -ENODEV;
		goto out_attach_fail;
	}
		ioc->hide_drives = 0; 
	shost->nr_hw_queues = 1;
	if (shost->host_tagset) {
		shost->nr_hw_queues =
		    ioc->reply_queue_count - ioc->high_iops_queues;
		iopoll_q_count =
		    ioc->reply_queue_count - ioc->iopoll_q_start_index;
		shost->nr_maps = iopoll_q_count ? 3 : 1;
		dev_info(&ioc->pdev->dev,
		    "Max SCSIIO MPT commands: %d shared with nr_hw_queues = %d\n",
		    shost->can_queue, shost->nr_hw_queues);
	}
	rv = scsi_add_host(shost, &pdev->dev);
	if (rv) {
		ioc_err(ioc, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		goto out_add_shost_fail;
	}
	pr_err("important message:\n \
		ioc->is_gen35_ioc = %-8d	ioc->is_aero_ioc = %-8d		shost->host_tagset=%-8d	ioc->reply_queue_count=%-8d	\n \
		ioc->scsiio_depth = %-8d	ioc->hi_priority_depth = %-8d	ioc->internal_depth=%-8d		\n \
		shost->nr_hw_queues=%-8d	ioc->reply_sz=%-8d			ioc->request_sz=%-8d \n \
		ioc->sge_size = %-8d	ioc->max_sges_in_main_message = %-8d	ioc->max_sges_in_chain_message = %-8d \n \
		ioc->facts->RequestCredit = %-8d	ioc->facts->HighPriorityCredit = %-8d	ioc->hba_queue_depth = %-8d \n \
		ioc->chain_depth = %-8d	ioc->chains_needed_per_io = %-8d	ioc->chain_segment_sz=%-8d		\n \
		ioc->shost->can_queue=%-8d	ioc->reply_post_queue_depth=%-8d	ioc->reply_free_queue_depth=%-8d", \
		ioc->is_gen35_ioc,ioc->is_aero_ioc,shost->host_tagset,ioc->reply_queue_count, \
		ioc->scsiio_depth,ioc->hi_priority_depth,ioc->internal_depth, \
		shost->nr_hw_queues,ioc->reply_sz,ioc->request_sz, \
		ioc->sge_size,ioc->max_sges_in_main_message,ioc->max_sges_in_chain_message, \
		ioc->facts.RequestCredit,ioc->facts.HighPriorityCredit,ioc->hba_queue_depth,\
		ioc->chain_depth,ioc->chains_needed_per_io,ioc->chain_segment_sz, \
		ioc->shost->can_queue,ioc->reply_post_queue_depth,ioc->reply_free_queue_depth);
	scsi_scan_host(shost);
	return 0;
out_add_shost_fail:
	mpt3sas_base_detach(ioc);
out_attach_fail:
	destroy_workqueue(ioc->firmware_event_thread);
out_thread_fail:
	spin_lock(&gioc_lock);
	list_del(&ioc->list);
	spin_unlock(&gioc_lock);
	scsi_host_put(shost);
	return rv;
}
static const struct pci_device_id mpt3sas_pci_table[] = {
	{ MPI2_MFGPAGE_VENDORID_LSI, MPI25_MFGPAGE_DEVID_SAS3008,
		PCI_ANY_ID, PCI_ANY_ID }, 
	{ MPI2_MFGPAGE_VENDORID_LSI, MPI26_MFGPAGE_DEVID_SAS3408,
		PCI_ANY_ID, PCI_ANY_ID },
	{ MPI2_MFGPAGE_VENDORID_LSI, MPI26_MFGPAGE_DEVID_SAS3416,
		PCI_ANY_ID, PCI_ANY_ID },
	{0}     
};
MODULE_DEVICE_TABLE(pci, mpt3sas_pci_table);
static struct pci_driver mpt3sas_driver = {
	.name		= MPT3SAS_DRIVER_NAME,
	.id_table	= mpt3sas_pci_table,
	.probe		= _scsih_probe,
	.remove		= scsih_remove,
};
static int
scsih_init(void)
{
	mpt3_ids = 0;
	mpt3sas_base_initialize_callback_handler();
	scsi_io_cb_idx = mpt3sas_base_register_callback_handler(_scsih_io_done);
	base_cb_idx = mpt3sas_base_register_callback_handler(mpt3sas_base_done);
	port_enable_cb_idx = mpt3sas_base_register_callback_handler(
	    mpt3sas_port_enable_done);
	config_cb_idx = mpt3sas_base_register_callback_handler(
	    mpt3sas_config_done);
	return 0;
}
static void
scsih_exit(void)
{
	mpt3sas_base_release_callback_handler(scsi_io_cb_idx);
	mpt3sas_base_release_callback_handler(base_cb_idx);
	mpt3sas_base_release_callback_handler(port_enable_cb_idx);
	mpt3sas_base_release_callback_handler(config_cb_idx);
	sas_release_transport(mpt3sas_transport_template);
}
static int __init
_mpt3sas_init(void)
{
	int error;
	pr_info("%s version %s loaded\n", MPT3SAS_DRIVER_NAME,
					MPT3SAS_DRIVER_VERSION);
	mpt3sas_transport_template =
	    sas_attach_transport(&mpt3sas_transport_functions);
	if (!mpt3sas_transport_template)
		return -ENODEV;
	error = scsih_init();
	if (error) {
		scsih_exit();
		return error;
	}
	error = pci_register_driver(&mpt3sas_driver);
	if (error)
		scsih_exit();
	return error;
}
static void __exit
_mpt3sas_exit(void)
{
	pr_info("mpt3sas version %s unloading\n",
				MPT3SAS_DRIVER_VERSION);
	pci_unregister_driver(&mpt3sas_driver);
	scsih_exit();
}
module_init(_mpt3sas_init);
module_exit(_mpt3sas_exit);
