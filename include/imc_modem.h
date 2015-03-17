/*
 * tel-plugin-imc
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Hayoon Ko <hayoon.ko@samsung.com>
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

#ifndef __IMC_MODEM_H__
#define __IMC_MODEM_H__

gboolean imc_modem_init(TcorePlugin *cp, CoreObject *co_modem);
void imc_modem_exit(TcorePlugin *cp, CoreObject *co_modem);

gboolean modem_power_on(TcorePlugin *plugin);
void modem_register_nvm(CoreObject *co_modem);

#endif	// __IMC_MODEM_H__