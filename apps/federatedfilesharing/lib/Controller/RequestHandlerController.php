<?php
/**
 * @author Arthur Schiwon <blizzz@arthur-schiwon.de>
 * @author Björn Schießle <bjoern@schiessle.org>
 * @author Joas Schilling <coding@schilljs.com>
 * @author Lukas Reschke <lukas@statuscode.ch>
 * @author Morris Jobke <hey@morrisjobke.de>
 * @author Thomas Müller <thomas.mueller@tmit.eu>
 *
 * @copyright Copyright (c) 2018, ownCloud GmbH
 * @license AGPL-3.0
 *
 * This code is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License, version 3,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License, version 3,
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

namespace OCA\FederatedFileSharing\Controller;

use OC\OCS\Result;
use OCA\FederatedFileSharing\AddressHandler;
use OCA\FederatedFileSharing\Exception\NotSupportedException;
use OCA\FederatedFileSharing\Exception\InvalidShareException;
use OCA\FederatedFileSharing\FederatedShareProvider;
use OCA\FederatedFileSharing\FedShareManager;
use OCA\FederatedFileSharing\Notifications;
use OCP\App\IAppManager;
use OCP\AppFramework\Http;
use OCP\AppFramework\OCSController;
use OCP\Constants;
use OCP\IDBConnection;
use OCP\IRequest;
use OCP\IUserManager;
use OCP\Share;
use OCP\Share\IShare;

/**
 * Class RequestHandlerController
 *
 * Handles OCS Request to the federated share API
 *
 * @package OCA\FederatedFileSharing\API
 */
class RequestHandlerController extends OCSController {

	/** @var FederatedShareProvider */
	private $federatedShareProvider;

	/** @var IDBConnection */
	private $connection;

	/** @var IAppManager */
	private $appManager;
	/** @var IUserManager */
	private $userManager;

	/** @var Notifications */
	private $notifications;

	/** @var AddressHandler */
	private $addressHandler;

	/** @var  FedShareManager */
	private $fedShareManager;

	/**
	 * Server2Server constructor.
	 *
	 * @param string $appName
	 * @param IRequest $request
	 * @param FederatedShareProvider $federatedShareProvider
	 * @param IDBConnection $connection
	 * @param IAppManager $appManager
	 * @param IUserManager $userManager
	 * @param Notifications $notifications
	 * @param AddressHandler $addressHandler
	 * @param FedShareManager $fedShareManager
	 */
	public function __construct($appName,
								IRequest $request,
								FederatedShareProvider $federatedShareProvider,
								IDBConnection $connection,
								IAppManager $appManager,
								IUserManager $userManager,
								Notifications $notifications,
								AddressHandler $addressHandler,
								FedShareManager $fedShareManager
	) {
		parent::__construct($appName, $request);

		$this->federatedShareProvider = $federatedShareProvider;
		$this->connection = $connection;
		$this->appManager = $appManager;
		$this->userManager = $userManager;
		$this->notifications = $notifications;
		$this->addressHandler = $addressHandler;
		$this->fedShareManager = $fedShareManager;
	}

	/**
	 * @NoCSRFRequired
	 * @PublicPage
	 *
	 * create a new share
	 *
	 * @return Result
	 */
	public function createShare() {
		try {
			$this->assertIncomingSharingEnabled();
			$remote = $this->request->getParam('remote', null);
			$token = $this->request->getParam('token', null);
			$name = $this->request->getParam('name', null);
			$owner = $this->request->getParam('owner', null);
			$sharedBy = $this->request->getParam('sharedBy', null);
			$shareWith = $this->request->getParam('shareWith', null);
			$remoteId = $this->request->getParam('remoteId', null);
			$sharedByFederatedId = $this->request->getParam(
				'sharedByFederatedId',
				null
			);
			$ownerFederatedId = $this->request->getParam('ownerFederatedId', null);
			$hasMissingParams = $this->hasNull(
				[$remote, $token, $name, $owner, $remoteId, $shareWith]
			);
			if ($hasMissingParams) {
				throw new InvalidShareException(
					'server can not add remote share, missing parameter'
				);
			}
			if (!\OCP\Util::isValidFileName($name)) {
				throw new InvalidShareException(
					'The mountpoint name contains invalid characters.'
				);
			}
			// FIXME this should be a method in the user management instead
			\OCP\Util::writeLog('files_sharing', 'shareWith before, ' . $shareWith, \OCP\Util::DEBUG);
			\OCP\Util::emitHook(
				'\OCA\Files_Sharing\API\Server2Server',
				'preLoginNameUsedAsUserName',
				['uid' => &$shareWith]
			);
			\OCP\Util::writeLog('files_sharing', 'shareWith after, ' . $shareWith, \OCP\Util::DEBUG);
			if (!$this->userManager->userExists($shareWith)) {
				throw new InvalidShareException('User does not exist');
			}
			$this->fedShareManager->createShare(
				$shareWith,
				$remote,
				$remoteId,
				$owner,
				$name,
				$ownerFederatedId,
				$sharedByFederatedId,
				$sharedBy,
				$token
			);
		} catch (InvalidShareException $e) {
			return new Result(
				null,
				Http::STATUS_BAD_REQUEST,
				$e->getMessage()
			);
		} catch (NotSupportedException $e) {
			return new Result(
				null,
				Http::STATUS_SERVICE_UNAVAILABLE,
				'Server does not support federated cloud sharing'
			);
		} catch (\Exception $e) {
			\OCP\Util::writeLog(
				'files_sharing',
				'server can not add remote share, ' . $e->getMessage(),
				\OCP\Util::ERROR
			);
			return new Result(
				null,
				Http::STATUS_INTERNAL_SERVER_ERROR,
				'internal server error, was not able to add share from ' . $remote
			);
		}
		return new Result();
	}

	/**
	 * @NoCSRFRequired
	 * @PublicPage
	 *
	 * create re-share on behalf of another user
	 *
	 * @param int $id
	 *
	 * @return Result
	 */
	public function reShare($id) {
		$token = $this->request->getParam('token', null);
		$shareWith = $this->request->getParam('shareWith', null);
		$permission = (int)$this->request->getParam('permission', null);
		$remoteId = (int)$this->request->getParam('remoteId', null);

		if ($this->hasNull([$id, $token, $shareWith, $permission, $remoteId])) {
			return new Result(null, Http::STATUS_BAD_REQUEST);
		}

		try {
			$share = $this->federatedShareProvider->getShareById($id);

			// don't allow to share a file back to the owner
			list($user, $remote) = $this->addressHandler->splitUserRemote($shareWith);
			$owner = $share->getShareOwner();
			$currentServer = $this->addressHandler->generateRemoteURL();
			if ($this->addressHandler->compareAddresses($user, $remote, $owner, $currentServer)
				|| !$this->verifyShare($share, $token)
			) {
				return new Result(null, Http::STATUS_FORBIDDEN);
			}

			// check if re-sharing is allowed
			if (!$share->getPermissions() | ~Constants::PERMISSION_SHARE) {
				return new Result(null, Http::STATUS_BAD_REQUEST);
			}
			$share->setPermissions($share->getPermissions() & $permission);
			// the recipient of the initial share is now the initiator for the re-share
			$share->setSharedBy($share->getSharedWith());
			$share->setSharedWith($shareWith);

			$result = $this->federatedShareProvider->create($share);
			$this->federatedShareProvider->storeRemoteId((int)$result->getId(), $remoteId);
		} catch (Share\Exceptions\ShareNotFound $e) {
			return new Result(null, Http::STATUS_NOT_FOUND);
		} catch (\Exception $e) {
			return new Result(null, Http::STATUS_BAD_REQUEST);
		}

		return new Result(['token' => $result->getToken(), 'remoteId' => $result->getId()]);
	}

	/**
	 * @NoCSRFRequired
	 * @PublicPage
	 *
	 * accept server-to-server share
	 *
	 * @param int $id
	 *
	 * @return Result
	 */
	public function acceptShare($id) {
		try {
			$this->assertOutgoingSharingEnabled();

			$share = $this->getValidShare($id);
			$this->fedShareManager->acceptShare($share);
			if ($share->getShareOwner() !== $share->getSharedBy()) {
				list(, $remote) = $this->addressHandler->splitUserRemote(
					$share->getSharedBy()
				);
				$remoteId = $this->federatedShareProvider->getRemoteId($share);
				$this->notifications->sendAcceptShare(
					$remote,
					$remoteId,
					$share->getToken()
				);
			}
		} catch (NotSupportedException $e) {
			return new Result(
				null,
				Http::STATUS_SERVICE_UNAVAILABLE,
				'Server does not support federated cloud sharing'
			);
		} catch (Share\Exceptions\ShareNotFound $e) {
			// pass
		}
		return new Result();
	}

	/**
	 * @NoCSRFRequired
	 * @PublicPage
	 *
	 * decline server-to-server share
	 *
	 * @param int $id
	 *
	 * @return Result
	 */
	public function declineShare($id) {
		try {
			$this->assertOutgoingSharingEnabled();

			$share = $this->getValidShare($id);
			if ($share->getShareOwner() !== $share->getSharedBy()) {
				list(, $remote) = $this->addressHandler->splitUserRemote($share->getSharedBy());
				$remoteId = $this->federatedShareProvider->getRemoteId($share);
				$this->notifications->sendDeclineShare($remote, $remoteId, $share->getToken());
			}
			$this->fedShareManager->declineShare($share);
		} catch (NotSupportedException $e) {
			return new Result(
				null,
				Http::STATUS_SERVICE_UNAVAILABLE,
				'Server does not support federated cloud sharing'
			);
		} catch (Share\Exceptions\ShareNotFound $e) {
			// pass
		}

		return new Result();
	}

	/**
	 * @NoCSRFRequired
	 * @PublicPage
	 *
	 * remove server-to-server share if it was unshared by the owner
	 *
	 * @param int $id
	 *
	 * @return Result
	 */
	public function unshare($id) {
		try {
			$this->assertOutgoingSharingEnabled();
			$token = $this->request->getParam('token', null);
			$query = $this->connection->getQueryBuilder();
			$query->select('*')->from('share_external')
				->where(
					$query->expr()->eq(
						'remote_id', $query->createNamedParameter($id)
					)
				)
				->andWhere(
					$query->expr()->eq(
						'share_token',
						$query->createNamedParameter($token)
					)
				);
			$shareRow = $query->execute()->fetch();
			if ($token && $id && $shareRow !== false) {
				$this->fedShareManager->unshare($shareRow);
			}
		} catch (NotSupportedException $e) {
			return new Result(
				null,
				Http::STATUS_SERVICE_UNAVAILABLE,
				'Server does not support federated cloud sharing'
			);
		} catch (\Exception $e) {
			// pass
		}
		return new Result();
	}

	/**
	 * @NoCSRFRequired
	 * @PublicPage
	 *
	 * federated share was revoked, either by the owner or the re-sharer
	 *
	 * @param int $id
	 *
	 * @return Result
	 */
	public function revoke($id) {
		$token = $this->request->getParam('token');
		
		$share = $this->federatedShareProvider->getShareById($id);
		if (!$this->verifyShare($share, $token)) {
			return new Result(null, Http::STATUS_BAD_REQUEST);
		}

		$this->federatedShareProvider->removeShareFromTable($share);
		return new Result();
	}

	/**
	 * check if server-to-server sharing is enabled
	 *
	 * @param bool $incoming
	 *
	 * @return bool
	 */
	private function isS2SEnabled($incoming = false) {
		$result = \OCP\App::isEnabled('files_sharing');

		if ($incoming) {
			$result = $result && $this->federatedShareProvider->isIncomingServer2serverShareEnabled();
		} else {
			$result = $result && $this->federatedShareProvider->isOutgoingServer2serverShareEnabled();
		}

		return $result;
	}

	/**
	 * check if we got the right share
	 *
	 * @param Share\IShare $share
	 * @param string $token
	 *
	 * @return bool
	 */
	protected function verifyShare(Share\IShare $share, $token) {
		if (
			$share->getShareType() === FederatedShareProvider::SHARE_TYPE_REMOTE &&
			$share->getToken() === $token
		) {
			return true;
		}

		return false;
	}

	/**
	 * @NoCSRFRequired
	 * @PublicPage
	 *
	 * update share information to keep federated re-shares in sync
	 *
	 * @param array $params
	 *
	 * @return Result
	 */
	public function updatePermissions($params) {
		$id = (int)$params['id'];
		$token = $this->request->getParam('token', null);
		$permissions = $this->request->getParam('permissions', null);

		try {
			$share = $this->federatedShareProvider->getShareById($id);
			$validPermission = \ctype_digit($permissions);
			$validToken = $this->verifyShare($share, $token);
			if (!$validPermission || !$validToken) {
				return new Result(null, Http::STATUS_BAD_REQUEST);
			}
			$this->updatePermissionsInDatabase($share, (int)$permissions);
		} catch (Share\Exceptions\ShareNotFound $e) {
			return new Result(null, Http::STATUS_BAD_REQUEST);
		}

		return new Result();
	}

	/**
	 * update permissions in database
	 *
	 * @param IShare $share
	 * @param int $permissions
	 */
	protected function updatePermissionsInDatabase(IShare $share, $permissions) {
		$query = $this->connection->getQueryBuilder();
		$query->update('share')
			->where($query->expr()->eq('id', $query->createNamedParameter($share->getId())))
			->set('permissions', $query->createNamedParameter($permissions))
			->execute();
	}

	/**
	 * Get share by id, validate it's type and token
	 *
	 * @param int $id
	 *
	 * @return IShare
	 *
	 * @throws Share\Exceptions\ShareNotFound
	 * @throws InvalidShareException
	 */
	protected function getValidShare($id) {
		$share = $this->federatedShareProvider->getShareById($id);
		$token = $this->request->getParam('token', null);
		if ($share->getShareType() !== FederatedShareProvider::SHARE_TYPE_REMOTE
			|| $share->getToken() !== $token
		) {
			throw new InvalidShareException();
		}
		return $share;
	}

	/**
	 * Make sure that incoming shares are enabled
	 *
	 * @return void
	 *
	 * @throws NotSupportedException
	 */
	protected function assertIncomingSharingEnabled() {
		if (!$this->appManager->isEnabledForUser('files_sharing')
			|| !$this->federatedShareProvider->isIncomingServer2serverShareEnabled()
		) {
			throw new NotSupportedException();
		}
	}
	
	/**
	 * Make sure that outgoing shares are enabled
	 *
	 * @return void
	 *
	 * @throws NotSupportedException
	 */
	protected function assertOutgoingSharingEnabled() {
		if (!$this->appManager->isEnabledForUser('files_sharing')
			|| !$this->federatedShareProvider->isOutgoingServer2serverShareEnabled()
		) {
			throw new NotSupportedException();
		}
	}

	/**
	 * Check if value is null or an array has any null item
	 *
	 * @param mixed $param
	 *
	 * @return bool
	 */
	protected function hasNull($param) {
		if (\is_array($param)) {
			return \in_array(null, $param, true);
		} else {
			return $param === null;
		}
	}
}
