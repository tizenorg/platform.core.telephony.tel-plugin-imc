/*
 * tel-plugin-imc
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Ja-young Gu <jygu@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __S_DISPATCH_H__
#define __S_DISPATCH_H__

void do_factory(TcoreHal *h, const ipc_message_type *ipc);
void do_notification_message(TcorePlugin *p, const ipc_message_type *ipc);
void do_notification_sys_message(TcorePlugin *p, const void *data);

#endif
