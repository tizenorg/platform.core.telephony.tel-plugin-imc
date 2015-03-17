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

#ifndef __IMC_PHONEBOOK_H__
#define __IMC_PHONEBOOK_H__

gboolean imc_phonebook_init(TcorePlugin *cp, CoreObject *co_phonebook);
void imc_phonebook_exit(TcorePlugin *cp, CoreObject *co_phonebook);

#endif /* __IMC_PHONEBOOK_H__ */
